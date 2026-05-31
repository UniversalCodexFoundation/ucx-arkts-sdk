/*
 * SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * der.ets —— 最小 X.509 / DER 解析（仅取 UCX 验签所需字段）。
 *
 * UCX 的证书是自签名 X.509 v3、Ed25519（SPKI OID 1.3.101.112）。验签只需要：
 *   1. SubjectPublicKeyInfo 里的 32 字节原始 Ed25519 公钥。
 *   2. validity 的 notBefore / notAfter（判断证书时间窗口）。
 *   3. subject CN（用于 self-signed 判定与展示）。
 * **不做** CA 链 / 路径验证（参考实现把证书当自签名，信任内嵌公钥；信任策略交给应用）。
 *
 * 仅实现 DER 的 TLV 遍历所需的最小子集：tag / 长度（短/长格式）/ 内容偏移。
 * 不依赖任何平台 ASN.1 库（保持纯 ArkTS、跨版本一致、可审阅）。
 *
 * 证书结构（X.509）：
 *   Certificate ::= SEQUENCE {
 *     tbsCertificate SEQUENCE {
 *       [0] version, serialNumber, signature(AlgId), issuer(Name),
 *       validity SEQUENCE { notBefore Time, notAfter Time },
 *       subject(Name), subjectPublicKeyInfo SEQUENCE { AlgId, BIT STRING },
 *       ... extensions
 *     },
 *     signatureAlgorithm, signatureValue
 *   }
 *
 * ArkTS 注意：禁 any；时间用 epoch 毫秒（number）表示，便于与 Date.now() 比较。
 */

// DER tag 常量。
const TAG_SEQUENCE: number = 0x30;
const TAG_SET: number = 0x31;
const TAG_INTEGER: number = 0x02;
const TAG_BIT_STRING: number = 0x03;
const TAG_OID: number = 0x06;
const TAG_UTC_TIME: number = 0x17;
const TAG_GENERALIZED_TIME: number = 0x18;
const TAG_CONTEXT_0: number = 0xa0; // [0] EXPLICIT (version)

// Ed25519 的 SPKI AlgorithmIdentifier OID 编码（1.3.101.112）= 06 03 2B 65 70。
const ED25519_OID_BYTES: Uint8Array = new Uint8Array([0x2b, 0x65, 0x70]);
// CN（commonName）的 OID 2.5.4.3 = 06 03 55 04 03。
const CN_OID_BYTES: Uint8Array = new Uint8Array([0x55, 0x04, 0x03]);

/** 一个 DER TLV：tag、内容起止偏移、内容长度。 */
class Tlv {
  tag: number;
  contentStart: number;
  contentEnd: number;
  /** 整个 TLV（含 tag/len）结束偏移，用于顺序遍历。 */
  tlvEnd: number;

  constructor(tag: number, contentStart: number, contentEnd: number, tlvEnd: number) {
    this.tag = tag;
    this.contentStart = contentStart;
    this.contentEnd = contentEnd;
    this.tlvEnd = tlvEnd;
  }
}

/** 从 offset 处读取一个 TLV；失败返回 null。 */
function readTlv(data: Uint8Array, offset: number): Tlv | null {
  if (offset + 2 > data.length) {
    return null;
  }
  const tag: number = data[offset];
  let p: number = offset + 1;
  let len: number = data[p];
  p++;
  if (len < 0x80) {
    // 短格式。
  } else {
    const numBytes: number = len & 0x7f;
    if (numBytes === 0 || numBytes > 4 || p + numBytes > data.length) {
      return null;
    }
    len = 0;
    for (let i = 0; i < numBytes; i++) {
      len = (len << 8) | data[p];
      p++;
    }
  }
  const contentStart: number = p;
  const contentEnd: number = p + len;
  if (contentEnd > data.length) {
    return null;
  }
  return new Tlv(tag, contentStart, contentEnd, contentEnd);
}

/** 解析后的证书要素（验签所需）。 */
export class Certificate {
  /** 32 字节原始 Ed25519 公钥。 */
  publicKey: Uint8Array;
  /** notBefore（epoch 毫秒）。 */
  notBefore: number;
  /** notAfter（epoch 毫秒）。 */
  notAfter: number;
  /** subject CN（可能为空字符串）。 */
  subjectCn: string;
  /** issuer CN（可能为空字符串）；用于 self-signed 判定。 */
  issuerCn: string;

  constructor(
    publicKey: Uint8Array, notBefore: number, notAfter: number,
    subjectCn: string, issuerCn: string,
  ) {
    this.publicKey = publicKey;
    this.notBefore = notBefore;
    this.notAfter = notAfter;
    this.subjectCn = subjectCn;
    this.issuerCn = issuerCn;
  }

  /** 证书时间窗口在给定时刻（epoch 毫秒）内是否有效。 */
  isTimeValid(nowMs: number): boolean {
    return nowMs >= this.notBefore && nowMs <= this.notAfter;
  }

  /** 自签名判定：subject CN == issuer CN（与参考实现一致）。 */
  isSelfSigned(): boolean {
    return this.subjectCn === this.issuerCn;
  }
}

/** 比较 data[start..end) 是否以 needle 结尾匹配（OID 内容比对用）。 */
function contentEquals(data: Uint8Array, start: number, end: number, needle: Uint8Array): boolean {
  if (end - start !== needle.length) {
    return false;
  }
  for (let i = 0; i < needle.length; i++) {
    if (data[start + i] !== needle[i]) {
      return false;
    }
  }
  return true;
}

/**
 * 在一个 Name（RDNSequence）里查找 commonName（CN）的字符串值。
 * Name ::= SEQUENCE OF RelativeDistinguishedName(SET OF AttributeTypeAndValue)。
 * AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }。
 * 找到 type==2.5.4.3 时返回其 value 的字符串。找不到返回 ""。
 */
function findCn(data: Uint8Array, nameStart: number, nameEnd: number): string {
  let p: number = nameStart;
  while (p < nameEnd) {
    const rdn: Tlv | null = readTlv(data, p);
    if (rdn === null || rdn.tag !== TAG_SET) {
      break;
    }
    // 遍历 RDN 内的 AttributeTypeAndValue。
    let q: number = rdn.contentStart;
    while (q < rdn.contentEnd) {
      const atv: Tlv | null = readTlv(data, q);
      if (atv === null || atv.tag !== TAG_SEQUENCE) {
        break;
      }
      const typeTlv: Tlv | null = readTlv(data, atv.contentStart);
      if (typeTlv !== null && typeTlv.tag === TAG_OID &&
        contentEquals(data, typeTlv.contentStart, typeTlv.contentEnd, CN_OID_BYTES)) {
        // value 紧随其后。
        const valTlv: Tlv | null = readTlv(data, typeTlv.tlvEnd);
        if (valTlv !== null) {
          return decodeAsciiish(data, valTlv.contentStart, valTlv.contentEnd);
        }
      }
      q = atv.tlvEnd;
    }
    p = rdn.tlvEnd;
  }
  return '';
}

/** 把一段字节当作 UTF8String/PrintableString 解码（CN 一般为 ASCII/UTF-8）。 */
function decodeAsciiish(data: Uint8Array, start: number, end: number): string {
  let out: string = '';
  // 简单 UTF-8 解码（CN 通常是 PrintableString / UTF8String）。
  let i: number = start;
  while (i < end) {
    const b0: number = data[i];
    if (b0 < 0x80) {
      out += String.fromCharCode(b0);
      i++;
    } else if ((b0 & 0xe0) === 0xc0 && i + 1 < end) {
      const cp: number = ((b0 & 0x1f) << 6) | (data[i + 1] & 0x3f);
      out += String.fromCharCode(cp);
      i += 2;
    } else if ((b0 & 0xf0) === 0xe0 && i + 2 < end) {
      const cp: number = ((b0 & 0x0f) << 12) | ((data[i + 1] & 0x3f) << 6) | (data[i + 2] & 0x3f);
      out += String.fromCharCode(cp);
      i += 3;
    } else {
      out += String.fromCharCode(b0);
      i++;
    }
  }
  return out;
}

/** 解析 UTCTime / GeneralizedTime 为 epoch 毫秒。失败返回 NaN。 */
function parseDerTime(data: Uint8Array, tag: number, start: number, end: number): number {
  let s: string = '';
  for (let i = start; i < end; i++) {
    s += String.fromCharCode(data[i]);
  }
  // UTCTime: YYMMDDHHMMSSZ（YY < 50 -> 20YY，否则 19YY）。
  // GeneralizedTime: YYYYMMDDHHMMSSZ。
  let year: number;
  let rest: string;
  if (tag === TAG_UTC_TIME) {
    const yy: number = parseInt(s.substring(0, 2), 10);
    year = yy < 50 ? 2000 + yy : 1900 + yy;
    rest = s.substring(2);
  } else {
    year = parseInt(s.substring(0, 4), 10);
    rest = s.substring(4);
  }
  const month: number = parseInt(rest.substring(0, 2), 10);
  const day: number = parseInt(rest.substring(2, 4), 10);
  const hour: number = parseInt(rest.substring(4, 6), 10);
  const minute: number = parseInt(rest.substring(6, 8), 10);
  const second: number = rest.length >= 10 ? parseInt(rest.substring(8, 10), 10) : 0;
  if (!Number.isFinite(year) || !Number.isFinite(month) || !Number.isFinite(day)) {
    return NaN;
  }
  // 末尾 'Z' 表示 UTC。用 Date.UTC 构造（月份 0-based）。
  return Date.UTC(year, month - 1, day, hour, minute, second);
}

/**
 * 解析 X.509 证书 DER，提取 Ed25519 公钥 / 有效期 / CN。
 * 失败返回 null。
 */
export function parseCertificate(der: Uint8Array): Certificate | null {
  // Certificate ::= SEQUENCE。
  const cert: Tlv | null = readTlv(der, 0);
  if (cert === null || cert.tag !== TAG_SEQUENCE) {
    return null;
  }
  // tbsCertificate ::= SEQUENCE（第一个子元素）。
  const tbs: Tlv | null = readTlv(der, cert.contentStart);
  if (tbs === null || tbs.tag !== TAG_SEQUENCE) {
    return null;
  }

  let p: number = tbs.contentStart;
  // [0] version（可选，EXPLICIT）。
  let first: Tlv | null = readTlv(der, p);
  if (first === null) {
    return null;
  }
  if (first.tag === TAG_CONTEXT_0) {
    p = first.tlvEnd;
  }
  // serialNumber INTEGER。
  const serial: Tlv | null = readTlv(der, p);
  if (serial === null || serial.tag !== TAG_INTEGER) {
    return null;
  }
  p = serial.tlvEnd;
  // signature AlgorithmIdentifier SEQUENCE。
  const sigAlg: Tlv | null = readTlv(der, p);
  if (sigAlg === null || sigAlg.tag !== TAG_SEQUENCE) {
    return null;
  }
  p = sigAlg.tlvEnd;
  // issuer Name SEQUENCE。
  const issuer: Tlv | null = readTlv(der, p);
  if (issuer === null || issuer.tag !== TAG_SEQUENCE) {
    return null;
  }
  const issuerCn: string = findCn(der, issuer.contentStart, issuer.contentEnd);
  p = issuer.tlvEnd;
  // validity SEQUENCE { notBefore, notAfter }。
  const validity: Tlv | null = readTlv(der, p);
  if (validity === null || validity.tag !== TAG_SEQUENCE) {
    return null;
  }
  const nbTlv: Tlv | null = readTlv(der, validity.contentStart);
  if (nbTlv === null) {
    return null;
  }
  const naTlv: Tlv | null = readTlv(der, nbTlv.tlvEnd);
  if (naTlv === null) {
    return null;
  }
  const notBefore: number = parseDerTime(der, nbTlv.tag, nbTlv.contentStart, nbTlv.contentEnd);
  const notAfter: number = parseDerTime(der, naTlv.tag, naTlv.contentStart, naTlv.contentEnd);
  if (!Number.isFinite(notBefore) || !Number.isFinite(notAfter)) {
    return null;
  }
  p = validity.tlvEnd;
  // subject Name SEQUENCE。
  const subject: Tlv | null = readTlv(der, p);
  if (subject === null || subject.tag !== TAG_SEQUENCE) {
    return null;
  }
  const subjectCn: string = findCn(der, subject.contentStart, subject.contentEnd);
  p = subject.tlvEnd;
  // subjectPublicKeyInfo SEQUENCE { AlgorithmIdentifier, BIT STRING }。
  const spki: Tlv | null = readTlv(der, p);
  if (spki === null || spki.tag !== TAG_SEQUENCE) {
    return null;
  }
  // AlgorithmIdentifier SEQUENCE，内含 Ed25519 OID。
  const spkiAlg: Tlv | null = readTlv(der, spki.contentStart);
  if (spkiAlg === null || spkiAlg.tag !== TAG_SEQUENCE) {
    return null;
  }
  const algOid: Tlv | null = readTlv(der, spkiAlg.contentStart);
  if (algOid === null || algOid.tag !== TAG_OID ||
    !contentEquals(der, algOid.contentStart, algOid.contentEnd, ED25519_OID_BYTES)) {
    return null;
  }
  // BIT STRING（紧随 AlgorithmIdentifier）= 公钥。
  const bitStr: Tlv | null = readTlv(der, spkiAlg.tlvEnd);
  if (bitStr === null || bitStr.tag !== TAG_BIT_STRING) {
    return null;
  }
  // BIT STRING 第一个内容字节是 "unused bits" 计数，应为 0；其后 32 字节为公钥。
  const pkStart: number = bitStr.contentStart + 1;
  const pkLen: number = bitStr.contentEnd - pkStart;
  if (pkLen !== 32) {
    return null;
  }
  const publicKey: Uint8Array = new Uint8Array(32);
  publicKey.set(der.subarray(pkStart, pkStart + 32));

  return new Certificate(publicKey, notBefore, notAfter, subjectCn, issuerCn);
}
