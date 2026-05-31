/*
 * SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * signature.ets —— 双层签名的二进制结构解析与摘要计算（UCX-FORMAT §6）。
 *
 * 本文件只做「无 I/O 的纯字节」工作，供 verify.ets 编排：
 *   - Layer 1 `.EC` blob 解析（algoId|sigLen|sig64|certLen|certDER）。
 *   - Layer 1 `.SF` 文本里 BLAKE3-Digest-Manifest 字段提取。
 *   - Layer 2 UCX 签名块定位（EOCD -> CD offset -> magic -> size_of_block）。
 *   - Layer 2 签名块解析（signers_data -> signed_data / signature / public_key）。
 *   - Layer 2 protected-content 重组 + 分块 BLAKE3 摘要（chunk 前缀 0xA5 / top 0x5A）。
 *
 * 整数一律小端（LE）。所有越界 / 非法都返回 null，由 verify.ets 折叠为「该层无效」。
 *
 * ArkTS 注意：禁 any；显式类型；复用 blake3.ets / util.ets。
 */

import {
  L2_BLOCK_MAGIC, L2_PAIR_ID, L2_CHUNK_PREFIX, L2_TOP_PREFIX, L2_CHUNK_SIZE,
  SIG_ALGO_ED25519_BLAKE3, ED25519_SIG_LEN, ED25519_PUBKEY_LEN,
} from './constants';
import { blake3 } from './blake3';
import { readU16LE, readU32LE, readU64LE, concatBytes, sliceCopy, u32le, bytesEqual } from './util';

// ── Layer 1：.EC blob ─────────────────────────────────────────────────────

/** 解析后的 Layer 1 .EC 内容。 */
export class EcBlob {
  signature: Uint8Array; // 64 字节
  certDer: Uint8Array;
  constructor(signature: Uint8Array, certDer: Uint8Array) {
    this.signature = signature;
    this.certDer = certDer;
  }
}

/**
 * 解析 `.EC` 二进制 blob：
 *   algoId u32LE | sigLen u32LE | sig(sigLen) | certLen u32LE | certDER(certLen)。
 * algoId 必须为 0x0001（Ed25519+BLAKE3），sigLen 必须为 64。失败返回 null。
 */
export function parseEcBlob(data: Uint8Array): EcBlob | null {
  if (data.length < 8) {
    return null;
  }
  let o: number = 0;
  const algoId: number = readU32LE(data, o);
  o += 4;
  if (algoId !== SIG_ALGO_ED25519_BLAKE3) {
    return null;
  }
  const sigLen: number = readU32LE(data, o);
  o += 4;
  if (sigLen !== ED25519_SIG_LEN || o + sigLen > data.length) {
    return null;
  }
  const signature: Uint8Array = sliceCopy(data, o, o + sigLen);
  o += sigLen;
  if (o + 4 > data.length) {
    return null;
  }
  const certLen: number = readU32LE(data, o);
  o += 4;
  if (certLen <= 0 || o + certLen > data.length) {
    return null;
  }
  const certDer: Uint8Array = sliceCopy(data, o, o + certLen);
  return new EcBlob(signature, certDer);
}

/**
 * 从 `.SF` 文本中提取 `BLAKE3-Digest-Manifest` 字段值（Base64 字符串）。
 * 找不到返回 null。
 */
export function extractSfManifestDigest(sfText: string): string | null {
  const lines: string[] = sfText.split('\r\n').join('\n').split('\n');
  const prefix: string = 'BLAKE3-Digest-Manifest: ';
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].indexOf(prefix) === 0) {
      return lines[i].substring(prefix.length);
    }
  }
  return null;
}

// ── Layer 2：签名块定位与解析 ──────────────────────────────────────────────

/** Layer 2 单个签名者条目。 */
export class L2Signer {
  /** 32 字节存储的 protected-content 摘要（待与重算值比对）。 */
  digest: Uint8Array;
  certDer: Uint8Array;
  signature: Uint8Array; // 64 字节
  publicKey: Uint8Array; // 32 字节
  /** Ed25519 验签覆盖的 signed_data 字节（algoId‖digest‖certLen‖certDER）。 */
  signedData: Uint8Array;
  constructor(
    digest: Uint8Array, certDer: Uint8Array, signature: Uint8Array,
    publicKey: Uint8Array, signedData: Uint8Array,
  ) {
    this.digest = digest;
    this.certDer = certDer;
    this.signature = signature;
    this.publicKey = publicKey;
    this.signedData = signedData;
  }
}

/** Layer 2 定位结果：块在文件中的位置 + EOCD/CD 偏移（重组要用）。 */
export class L2Location {
  blockStart: number;
  cdOffset: number;
  eocdOffset: number;
  blockSize: number; // 整个块字节数（cd_offset - block_start）
  constructor(blockStart: number, cdOffset: number, eocdOffset: number, blockSize: number) {
    this.blockStart = blockStart;
    this.cdOffset = cdOffset;
    this.eocdOffset = eocdOffset;
    this.blockSize = blockSize;
  }
}

/**
 * 反向扫描定位 EOCD，返回 (eocdOffset, cdOffset)。找不到合法 EOCD 返回 null。
 * 与 zip.ets 的 findEocd 逻辑一致（此处独立实现，避免循环依赖 ZipView）。
 */
function locateEocd(data: Uint8Array): number[] | null {
  const minEocd: number = 22;
  if (data.length < minEocd) {
    return null;
  }
  const maxBack: number = Math.min(data.length, minEocd + 0xffff);
  const start: number = data.length - minEocd;
  const lowerBound: number = data.length - maxBack;
  for (let i = start; i >= lowerBound; i--) {
    if (data[i] === 0x50 && data[i + 1] === 0x4b && data[i + 2] === 0x05 && data[i + 3] === 0x06) {
      const commentLen: number = readU16LE(data, i + 20);
      if (i + minEocd + commentLen === data.length) {
        const cdOffset: number = readU32LE(data, i + 16);
        return [i, cdOffset];
      }
    }
  }
  return null;
}

/**
 * 定位 Layer 2 签名块（UCX-FORMAT §6.2.1）。
 *  1. 找 EOCD，读 CD offset。
 *  2. CD 前 16 字节必须等于 magic，否则无 Layer 2。
 *  3. 读 magic 前 8 字节的 trailing size_of_block；block_start = cd - 8 - size。
 *  4. 校验 block_start 处的 leading size_of_block 与 trailing 相等。
 * @returns 定位信息；无 Layer 2 或非法返回 null。
 */
export function locateL2Block(data: Uint8Array): L2Location | null {
  const eocd: number[] | null = locateEocd(data);
  if (eocd === null) {
    return null;
  }
  const eocdOffset: number = eocd[0];
  const cdOffset: number = eocd[1];
  if (cdOffset < 16 || cdOffset > data.length) {
    return null;
  }
  // CD 前 16 字节 == magic？
  const magicStart: number = cdOffset - 16;
  if (!bytesEqual(sliceCopy(data, magicStart, cdOffset), L2_BLOCK_MAGIC)) {
    return null;
  }
  // trailing size_of_block 在 magic_start - 8。
  if (magicStart < 8) {
    return null;
  }
  const sizeOfBlock: number = readU64LE(data, magicStart - 8);
  const blockStart: number = cdOffset - 8 - sizeOfBlock;
  if (blockStart < 0 || blockStart >= cdOffset) {
    return null;
  }
  // leading size_of_block 在 block_start。
  const leadingSize: number = readU64LE(data, blockStart);
  if (leadingSize !== sizeOfBlock) {
    return null;
  }
  return new L2Location(blockStart, cdOffset, eocdOffset, cdOffset - blockStart);
}

/**
 * 解析 Layer 2 签名块内的签名者数据（UCX-FORMAT §6.2）。
 * 块结构：size_of_block(8) | pair_size(8) | pair_id(4) | signers_data | size(8) | magic(16)。
 * @param block 整个签名块字节（data[blockStart..cdOffset]）。
 * @returns 签名者列表；非法返回 null（空列表也算非法）。
 */
export function parseL2Signers(block: Uint8Array): L2Signer[] | null {
  if (block.length < 8 + 8 + 4) {
    return null;
  }
  let o: number = 8; // 跳过 leading size_of_block
  const pairSize: number = readU64LE(block, o);
  o += 8;
  // [PAIRSIZE-GUARD] 验证 pairSize >= 4（至少容纳 pair_id），
  // 并且值在 JS 安全整数范围内（防止 u64 溢出后产生错误的 signersLen）。
  if (pairSize < 4 || pairSize > Number.MAX_SAFE_INTEGER) {
    return null;
  }
  const pairId: number = readU32LE(block, o);
  o += 4;
  if (pairId !== L2_PAIR_ID) {
    return null;
  }
  // signers_data 长度 = pairSize - 4。
  const signersLen: number = pairSize - 4;
  if (signersLen < 0 || o + signersLen > block.length) {
    return null;
  }
  const signersData: Uint8Array = sliceCopy(block, o, o + signersLen);

  // 解析一个签名者 blob：
  //  signed_data_length u32 | signed_data{ digestAlgoId u32 | digest 32 | certLen u32 | certDER }
  //  | sigAlgoId u32 | sigLen u32 | sig 64 | pubLen u32 | pub 32
  const signers: L2Signer[] = [];
  let p: number = 0;
  // 当前实现支持单签名者（参考实现写入一个 signer blob）；按顺序解析直至耗尽。
  while (p < signersData.length) {
    if (p + 4 > signersData.length) {
      break;
    }
    const signedDataLen: number = readU32LE(signersData, p);
    p += 4;
    if (signedDataLen < 4 + 32 + 4 || p + signedDataLen > signersData.length) {
      return null;
    }
    const signedData: Uint8Array = sliceCopy(signersData, p, p + signedDataLen);
    // 解析 signed_data 内部。
    let q: number = 0;
    const digestAlgoId: number = readU32LE(signedData, q);
    q += 4;
    if (digestAlgoId !== SIG_ALGO_ED25519_BLAKE3) {
      return null;
    }
    const digest: Uint8Array = sliceCopy(signedData, q, q + 32);
    q += 32;
    const certLen: number = readU32LE(signedData, q);
    q += 4;
    if (q + certLen > signedData.length) {
      return null;
    }
    const certDer: Uint8Array = sliceCopy(signedData, q, q + certLen);
    p += signedDataLen;

    // 签名三元组。
    if (p + 4 + 4 > signersData.length) {
      return null;
    }
    const sigAlgoId: number = readU32LE(signersData, p);
    p += 4;
    if (sigAlgoId !== SIG_ALGO_ED25519_BLAKE3) {
      return null;
    }
    const sigLen: number = readU32LE(signersData, p);
    p += 4;
    if (sigLen !== ED25519_SIG_LEN || p + sigLen > signersData.length) {
      return null;
    }
    const signature: Uint8Array = sliceCopy(signersData, p, p + sigLen);
    p += sigLen;
    if (p + 4 > signersData.length) {
      return null;
    }
    const pubLen: number = readU32LE(signersData, p);
    p += 4;
    if (pubLen !== ED25519_PUBKEY_LEN || p + pubLen > signersData.length) {
      return null;
    }
    const publicKey: Uint8Array = sliceCopy(signersData, p, p + pubLen);
    p += pubLen;

    signers.push(new L2Signer(digest, certDer, signature, publicKey, signedData));
  }

  if (signers.length === 0) {
    return null;
  }
  return signers;
}

/**
 * 重组「去签名块」的原始 ZIP，并计算 protected-content 分块摘要（UCX-FORMAT §6.2.2）。
 *
 * 重组：original = data[0..blockStart] ‖ data[cdOffset..end]；
 * 然后把 EOCD 的 CD-offset 字段回填为 (cdOffset - blockSize)。
 *
 * 分块摘要：
 *   chunk_digest[i] = BLAKE3( 0xA5 ‖ u32le(len(chunk_i)) ‖ chunk_i )，块 1 MiB。
 *   top = BLAKE3( 0x5A ‖ u32le(chunk_count) ‖ chunk_digest[0] ‖ ... )。
 * @returns 32 字节 top 摘要。
 */
export function computeL2ProtectedDigest(data: Uint8Array, loc: L2Location): Uint8Array {
  // section1 = entries（data[0..blockStart]）。
  const section1: Uint8Array = sliceCopy(data, 0, loc.blockStart);
  // section3+4 = CD..end（data[cdOffset..end]）。
  const cdAndEocd: Uint8Array = sliceCopy(data, loc.cdOffset, data.length);
  // 拼接重组。
  const original: Uint8Array = concatBytes([section1, cdAndEocd]);

  // 回填 EOCD 的 CD-offset 字段（EOCD+16，u32 LE）为 cdOffset - blockSize。
  // 重组后 EOCD 在 original 里的位置：原 eocdOffset - blockSize（块被移除，整体前移 blockSize）。
  const newEocdOffset: number = loc.eocdOffset - loc.blockSize;
  const newCdOffset: number = loc.cdOffset - loc.blockSize;
  if (newEocdOffset + 20 <= original.length) {
    original[newEocdOffset + 16] = newCdOffset & 0xff;
    original[newEocdOffset + 17] = (newCdOffset >>> 8) & 0xff;
    original[newEocdOffset + 18] = (newCdOffset >>> 16) & 0xff;
    original[newEocdOffset + 19] = (newCdOffset >>> 24) & 0xff;
  }

  // 分块摘要。
  return chunkedDigest(original);
}

/** 对 protected 字节做分块 BLAKE3 摘要（chunk 前缀 0xA5，top 前缀 0x5A）。 */
function chunkedDigest(protectedBytes: Uint8Array): Uint8Array {
  const total: number = protectedBytes.length;
  let chunkCount: number = Math.ceil(total / L2_CHUNK_SIZE);
  if (chunkCount === 0) {
    chunkCount = 1; // 空输入 -> 一个空 chunk
  }
  const chunkDigests: Uint8Array[] = [];
  for (let i = 0; i < chunkCount; i++) {
    const start: number = i * L2_CHUNK_SIZE;
    const end: number = Math.min(start + L2_CHUNK_SIZE, total);
    const chunk: Uint8Array = sliceCopy(protectedBytes, start, end);
    // chunk_digest[i] = BLAKE3( 0xA5 ‖ u32le(len) ‖ chunk )。
    const prefixed: Uint8Array = concatBytes([
      new Uint8Array([L2_CHUNK_PREFIX]), u32le(chunk.length), chunk,
    ]);
    chunkDigests.push(blake3(prefixed));
  }
  // top = BLAKE3( 0x5A ‖ u32le(chunk_count) ‖ chunk_digest... )。
  const topParts: Uint8Array[] = [];
  topParts.push(new Uint8Array([L2_TOP_PREFIX]));
  topParts.push(u32le(chunkCount));
  for (let i = 0; i < chunkDigests.length; i++) {
    topParts.push(chunkDigests[i]);
  }
  return blake3(concatBytes(topParts));
}
