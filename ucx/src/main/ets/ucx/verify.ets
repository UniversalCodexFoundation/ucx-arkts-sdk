/*
 * SPDX-License-Identifier: MIT
 *
 * verify.ets —— 双层签名验证编排 + 状态机（UCX-FORMAT §6）。
 *
 * Layer 1（JAR 风格 SF/EC，每签名者）：
 *   1. 找 META-INF/signatures/*.SF，signerId = 文件名 stem。
 *   2. Base64(BLAKE3(整个 MANIFEST.MF)) 与 SF 的 BLAKE3-Digest-Manifest 比对。
 *   3. 用 .EC 内嵌证书的 Ed25519 公钥验签 over .SF 原始字节。
 *   4. 校验证书时间窗口。
 *   5. 若存在 META-INF/certs/{SIGNER}.cert.pem，要求其 DER 与 .EC 内证书逐字节相等。
 *   signer 有效 ⟺ digest_matches && sig_valid && cert_time_valid && cert_pem_match。
 *   Layer 1 有效 ⟺ 所有 signer 有效。
 *
 * Layer 2（APK-v2 风格签名块）：
 *   1. 定位签名块；解析 signers。
 *   2. 重组「去块」ZIP，回填 EOCD 的 CD-offset，分块 BLAKE3 得 top digest。
 *   3. 每签名者：stored digest == recomputed && Ed25519(sig over signed_data) && cert_time_valid。
 *   Layer 2 有效 ⟺ 所有 signer 有效且 ≥1。
 *
 * 状态机（UCX-FORMAT §6 状态表）：两层都在→任一失败即 INVALID；仅一层在且有效→
 * VALID_WITH_WARNINGS；都不在→UNSIGNED；两层都在且都有效→VERIFIED。
 *
 * 指纹 = lowercase-hex BLAKE3(certDER)（64 hex），用于 L1/L2 签名者匹配与展示。
 *
 * ArkTS 注意：禁 any；时间用 Date.now()（epoch 毫秒）。
 */

import { ZipView } from './zip';
import {
  SignatureResult, SignatureStatus, Signer,
} from './types';
import { blake3 } from './blake3';
import { ed25519Verify } from './ed25519';
import { parseCertificate, Certificate } from './der';
import {
  parseEcBlob, EcBlob, extractSfManifestDigest,
  locateL2Block, L2Location, parseL2Signers, L2Signer, computeL2ProtectedDigest,
} from './signature';
import { fromBase64, toHex, utf8Decode, constantTimeEqual } from './util';

/**
 * 解码 PEM（CERTIFICATE 标签）为 DER 字节；失败返回 null。
 *
 * [P2 de-duplicate] 使用 util.fromBase64 替代原先内联的 base64DecodeStandard，
 * 消除重复的 Base64 解码实现（audit finding: verify.ets:64 重复 Base64 解码）。
 */
function pemToDer(pem: string, label: string): Uint8Array | null {
  const begin: string = `-----BEGIN ${label}-----`;
  const end: string = `-----END ${label}-----`;
  const bi: number = pem.indexOf(begin);
  const ei: number = pem.indexOf(end);
  if (bi < 0 || ei < 0 || ei <= bi) {
    return null;
  }
  const body: string = pem.substring(bi + begin.length, ei);
  // 去掉所有空白后 Base64 解码。
  let b64: string = '';
  for (let i = 0; i < body.length; i++) {
    const c: string = body.charAt(i);
    if (c !== '\n' && c !== '\r' && c !== ' ' && c !== '\t') {
      b64 += c;
    }
  }
  return fromBase64(b64);
}

/** 证书指纹：lowercase-hex BLAKE3(certDER)。 */
function certFingerprint(certDer: Uint8Array): string {
  return toHex(blake3(certDer));
}

/** Layer 1 单签名者验证的内部结果。 */
class L1Result {
  signerId: string;
  valid: boolean;
  fingerprint: string;
  subjectCn: string;
  certType: string;
  constructor(signerId: string, valid: boolean, fingerprint: string, subjectCn: string, certType: string) {
    this.signerId = signerId;
    this.valid = valid;
    this.fingerprint = fingerprint;
    this.subjectCn = subjectCn;
    this.certType = certType;
  }
}

/** 收集所有 .SF 的 signerId（文件名 stem）。 */
function collectSigners(zip: ZipView): string[] {
  const out: string[] = [];
  const prefix: string = 'META-INF/signatures/';
  const suffix: string = '.SF';
  for (let i = 0; i < zip.order.length; i++) {
    const name: string = zip.order[i];
    if (name.indexOf(prefix) === 0 && name.length > prefix.length + suffix.length &&
      name.substring(name.length - suffix.length) === suffix) {
      const stem: string = name.substring(prefix.length, name.length - suffix.length);
      out.push(stem);
    }
  }
  return out;
}

/** 验证 Layer 1 的单个签名者。 */
function verifyL1Signer(zip: ZipView, signerId: string, nowMs: number): L1Result {
  const sfName: string = `META-INF/signatures/${signerId}.SF`;
  const ecName: string = `META-INF/signatures/${signerId}.EC`;
  const pemName: string = `META-INF/certs/${signerId}.cert.pem`;

  const sfBytes: Uint8Array | undefined = zip.get(sfName);
  const ecBytes: Uint8Array | undefined = zip.get(ecName);
  const manifestBytes: Uint8Array | undefined = zip.get('META-INF/MANIFEST.MF');
  if (sfBytes === undefined || ecBytes === undefined || manifestBytes === undefined) {
    return new L1Result(signerId, false, '', '', '');
  }

  // 2) digest_matches：Base64(BLAKE3(MANIFEST.MF)) == SF 的 BLAKE3-Digest-Manifest。
  // [CT-DIGEST] 使用常量时间比较，防止计时侧信道泄露摘要内容。
  const manifestDigestBytes: Uint8Array = blake3(manifestBytes);
  const sfText: string = utf8Decode(sfBytes);
  const sfDigest: string | null = extractSfManifestDigest(sfText);
  let digestMatches: boolean = false;
  if (sfDigest !== null) {
    const sfDigestBytes: Uint8Array | null = fromBase64(sfDigest);
    digestMatches = sfDigestBytes !== null && constantTimeEqual(sfDigestBytes, manifestDigestBytes);
  }

  // 3) sig_valid：用 .EC 内证书的 Ed25519 公钥验签 over .SF 原始字节。
  const ec: EcBlob | null = parseEcBlob(ecBytes);
  let sigValid: boolean = false;
  let fingerprint: string = '';
  let subjectCn: string = '';
  let certType: string = '';
  let certTimeValid: boolean = false;
  let certPemMatch: boolean = true;
  if (ec !== null) {
    const cert: Certificate | null = parseCertificate(ec.certDer);
    if (cert !== null) {
      fingerprint = certFingerprint(ec.certDer);
      subjectCn = cert.subjectCn;
      certType = cert.isSelfSigned() ? 'self-signed' : 'ca-issued';
      sigValid = ed25519Verify(sfBytes, ec.signature, cert.publicKey);
      certTimeValid = cert.isTimeValid(nowMs);

      // 5) cert-PEM 交叉校验（若存在）。
      // [CT-DIGEST] 使用常量时间比较证书 DER 字节，防止计时侧信道。
      const pemBytes: Uint8Array | undefined = zip.get(pemName);
      if (pemBytes !== undefined) {
        const pemText: string = utf8Decode(pemBytes);
        const pemDer: Uint8Array | null = pemToDer(pemText, 'CERTIFICATE');
        certPemMatch = pemDer !== null && constantTimeEqual(pemDer, ec.certDer);
      }
    }
  }

  const valid: boolean = digestMatches && sigValid && certTimeValid && certPemMatch;
  return new L1Result(signerId, valid, fingerprint, subjectCn, certType);
}

/** Layer 2 单签名者验证的内部结果。 */
class L2SignerResult {
  valid: boolean;
  fingerprint: string;
  subjectCn: string;
  certType: string;
  constructor(valid: boolean, fingerprint: string, subjectCn: string, certType: string) {
    this.valid = valid;
    this.fingerprint = fingerprint;
    this.subjectCn = subjectCn;
    this.certType = certType;
  }
}

/** 验证 Layer 2（返回每签名者结果；无 Layer 2 返回 null）。 */
function verifyL2(data: Uint8Array, nowMs: number): L2SignerResult[] | null {
  const loc: L2Location | null = locateL2Block(data);
  if (loc === null) {
    return null;
  }
  const block: Uint8Array = data.subarray(loc.blockStart, loc.cdOffset);
  const signers: L2Signer[] | null = parseL2Signers(block);
  if (signers === null) {
    // 块存在但解析失败 -> 视为存在且无效（返回单个无效条目）。
    return [new L2SignerResult(false, '', '', '')];
  }
  // 重组 + 分块 BLAKE3。注意 computeL2ProtectedDigest 会回填 EOCD，需传入拷贝避免改动原 data。
  const dataCopy: Uint8Array = new Uint8Array(data.length);
  dataCopy.set(data);
  const recomputed: Uint8Array = computeL2ProtectedDigest(dataCopy, loc);

  const results: L2SignerResult[] = [];
  for (let i = 0; i < signers.length; i++) {
    const s: L2Signer = signers[i];
    const digestMatches: boolean = constantTimeEqual(s.digest, recomputed);
    // Ed25519 验签 over signed_data，用块内 public_key。
    const sigValid: boolean = ed25519Verify(s.signedData, s.signature, s.publicKey);
    const cert: Certificate | null = parseCertificate(s.certDer);
    let certTimeValid: boolean = false;
    let subjectCn: string = '';
    let certType: string = '';
    if (cert !== null) {
      certTimeValid = cert.isTimeValid(nowMs);
      subjectCn = cert.subjectCn;
      certType = cert.isSelfSigned() ? 'self-signed' : 'ca-issued';
    }
    const fingerprint: string = certFingerprint(s.certDer);
    const valid: boolean = digestMatches && sigValid && certTimeValid;
    results.push(new L2SignerResult(valid, fingerprint, subjectCn, certType));
  }
  return results;
}

/**
 * 综合双层签名验证，返回 SignatureResult（含状态机判定，UCX-FORMAT §6）。
 * @param zip 已解析的 ZipView（取 SF/EC/cert 与 MANIFEST）。
 * @param data 原始磁盘字节（Layer 2 需要）。
 */
export function verifySignatures(zip: ZipView, data: Uint8Array): SignatureResult {
  const nowMs: number = Date.now();

  // ── Layer 1 ──
  const signerIds: string[] = collectSigners(zip);
  const layer1Present: boolean = signerIds.length > 0;
  const l1Results: L1Result[] = [];
  let layer1Valid: boolean = layer1Present;
  for (let i = 0; i < signerIds.length; i++) {
    const r: L1Result = verifyL1Signer(zip, signerIds[i], nowMs);
    l1Results.push(r);
    if (!r.valid) {
      layer1Valid = false;
    }
  }

  // ── Layer 2 ──
  const l2Results: L2SignerResult[] | null = verifyL2(data, nowMs);
  const layer2Present: boolean = l2Results !== null;
  let layer2Valid: boolean = false;
  if (l2Results !== null) {
    layer2Valid = l2Results.length > 0;
    for (let i = 0; i < l2Results.length; i++) {
      if (!l2Results[i].valid) {
        layer2Valid = false;
      }
    }
  }

  // ── 合并 signer 列表（按 signerId / fingerprint 匹配 L1 与 L2）──
  const signers: Signer[] = [];
  for (let i = 0; i < l1Results.length; i++) {
    const r: L1Result = l1Results[i];
    // 在 L2 里找同指纹的条目，确定 layer2Valid（每签名者）。
    let l2v: boolean = false;
    if (l2Results !== null) {
      for (let j = 0; j < l2Results.length; j++) {
        if (l2Results[j].fingerprint !== '' && l2Results[j].fingerprint === r.fingerprint) {
          l2v = l2Results[j].valid;
        }
      }
    }
    const signer: Signer = {
      signerId: r.signerId,
      layer1Valid: r.valid,
      layer2Valid: l2v,
    };
    if (r.subjectCn !== '') signer.subjectCn = r.subjectCn;
    if (r.fingerprint !== '') signer.fingerprint = r.fingerprint;
    if (r.certType !== '') signer.certType = r.certType;
    signers.push(signer);
  }
  // 若有仅 L2 存在的签名者（L1 无对应），也补入。
  if (l2Results !== null) {
    for (let j = 0; j < l2Results.length; j++) {
      const fp: string = l2Results[j].fingerprint;
      let found: boolean = false;
      for (let i = 0; i < signers.length; i++) {
        if (signers[i].fingerprint === fp && fp !== '') {
          found = true;
        }
      }
      if (!found) {
        const signer: Signer = {
          signerId: '',
          layer1Valid: false,
          layer2Valid: l2Results[j].valid,
        };
        if (l2Results[j].subjectCn !== '') signer.subjectCn = l2Results[j].subjectCn;
        if (fp !== '') signer.fingerprint = fp;
        if (l2Results[j].certType !== '') signer.certType = l2Results[j].certType;
        signers.push(signer);
      }
    }
  }

  // ── 状态机（UCX-FORMAT §6 状态表）──
  const status: SignatureStatus = decideStatus(
    layer1Present, layer1Valid, layer2Present, layer2Valid,
  );

  return {
    status: status,
    layer1Present: layer1Present,
    layer1Valid: layer1Present && layer1Valid,
    layer2Present: layer2Present,
    layer2Valid: layer2Present && layer2Valid,
    signers: signers,
  };
}

/** 状态判定（UCX-FORMAT §6 状态表）。 */
function decideStatus(
  l1Present: boolean, l1Valid: boolean, l2Present: boolean, l2Valid: boolean,
): SignatureStatus {
  if (!l1Present && !l2Present) {
    return SignatureStatus.UNSIGNED;
  }
  if (l1Present && l2Present) {
    // 两层都在：任一失败即 INVALID；都有效即 VERIFIED。
    return (l1Valid && l2Valid) ? SignatureStatus.VERIFIED : SignatureStatus.INVALID;
  }
  // 仅一层在。
  if (l1Present) {
    return l1Valid ? SignatureStatus.VALID_WITH_WARNINGS : SignatureStatus.INVALID;
  }
  // 仅 L2 在。
  return l2Valid ? SignatureStatus.VALID_WITH_WARNINGS : SignatureStatus.INVALID;
}
