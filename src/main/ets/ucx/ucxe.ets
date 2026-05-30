/*
 * SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * ucxe.ets —— UCXE 加密容器头部解析 + 解密编排（UCX-FORMAT §7）。
 *
 * 职责：
 *   1. 解析 UCXE 二进制头（magic/ver/algo/kdf/flags/KDF参数/salt/iv/ct/tag）。
 *   2. 根据 algo + kdf 分派密钥获取（直接密钥 / 口令 KDF）与解密路径。
 *   3. 构造正确的 AAD（AEAD 用 header(8)‖kdf_params‖salt；CBC 的 HMAC 用 header(8)）。
 *   4. 处理分块模式（§7.7）：base nonce + 每块 nonce 拼接 + 每块独立 tag。
 *   5. 统一把所有失败折叠为不透明 DecryptionError（防 oracle）。
 *
 * 头部字段序（整数 LE，UCX-FORMAT §7.2）：
 *   magic(4) | version(1) | algo(1) | kdf(1) | flags(1)
 *   | KDF参数(0/4/12) | saltLen(u16) | salt | ivLen(u16) | iv
 *   | ctLen(u64) | ct | tag(算法定长，无长度前缀)
 *
 * AAD（load-bearing，UCX-FORMAT §7.6）：
 *   - AEAD（GCM / ChaCha20）：AAD = header(8) ‖ kdf_params(0|4|12) ‖ salt。
 *     header(8) 用**磁盘原始 flags 字节**（含 reserved bits）。分块模式每块都用同一 AAD。
 *   - AES-CBC：HMAC 覆盖 header(8) ‖ iv ‖ ciphertext，aad = header(8) **仅头部**。
 *
 * ArkTS 注意：禁 any；解密成功返回 Uint8Array，失败返回 null（调用方折叠为 DecryptionError）。
 */

import {
  UCXE_MAGIC, UCXE_FORMAT_VERSION,
  ALGO_AES_256_GCM, ALGO_AES_256_CBC, ALGO_CHACHA20_POLY1305,
  KDF_NONE, KDF_ARGON2ID, KDF_PBKDF2_HMAC_SHA256,
  AEAD_NONCE_LEN, CBC_IV_LEN, GCM_TAG_LEN, CHACHA_TAG_LEN, CBC_MAC_LEN,
} from './constants';
import { readU16LE, readU32LE, readU64LE, concatBytes, u32be, sliceCopy } from './util';
import { aesGcmDecrypt } from './aes';
import { chacha20Poly1305Decrypt } from './chacha20poly1305';
import { aesCbcHmacDecrypt } from './cbc';
import {
  KdfParams, validateKdfParams, deriveKeyFromPassphrase,
} from './kdf';

// 解析时的安全上界（UCX-FORMAT §7.2，拒绝而非崩溃）。
const MAX_SALT: number = 1024;
const MAX_IV: number = 256;
const MAX_CT: number = 16 * 1024 * 1024 * 1024; // 16 GiB
// 分块（§7.7）。
const UCXE_CHUNK_TAG_LEN: number = 16; // 分块仅 AEAD，每块 16 字节 tag

/** 解析后的 UCXE 头部 + 载荷切片。 */
export class UcxeHeader {
  /** 磁盘原始 8 字节头（magic‖ver‖algo‖kdf‖flags），AAD / HMAC 用其原始字节。 */
  header8: Uint8Array;
  algorithm: number;
  kdfId: number;
  /** 原始 flags 字节（含 reserved bits）。 */
  flags: number;
  /** 是否分块模式（flags bit0）。 */
  chunked: boolean;
  /** KDF 参数（含原始 LE 字节）。 */
  kdfParams: KdfParams;
  salt: Uint8Array;
  iv: Uint8Array;
  /** 密文（分块模式下为序列化的 chunk stream）。 */
  ciphertext: Uint8Array;
  /** 顶层 tag（分块模式下为零占位）。 */
  tag: Uint8Array;

  constructor(
    header8: Uint8Array, algorithm: number, kdfId: number, flags: number,
    chunked: boolean, kdfParams: KdfParams, salt: Uint8Array, iv: Uint8Array,
    ciphertext: Uint8Array, tag: Uint8Array,
  ) {
    this.header8 = header8;
    this.algorithm = algorithm;
    this.kdfId = kdfId;
    this.flags = flags;
    this.chunked = chunked;
    this.kdfParams = kdfParams;
    this.salt = salt;
    this.iv = iv;
    this.ciphertext = ciphertext;
    this.tag = tag;
  }
}

/** 前 4 字节是否等于 UCXE magic。 */
export function isUcxe(data: Uint8Array): boolean {
  if (data.length < 4) {
    return false;
  }
  return (
    data[0] === UCXE_MAGIC[0] &&
    data[1] === UCXE_MAGIC[1] &&
    data[2] === UCXE_MAGIC[2] &&
    data[3] === UCXE_MAGIC[3]
  );
}

/** 给定算法 id 返回 tag 长度；未知算法返回 -1。 */
function tagLenForAlgo(algo: number): number {
  if (algo === ALGO_AES_256_GCM) {
    return GCM_TAG_LEN;
  }
  if (algo === ALGO_CHACHA20_POLY1305) {
    return CHACHA_TAG_LEN;
  }
  if (algo === ALGO_AES_256_CBC) {
    return CBC_MAC_LEN;
  }
  return -1;
}

/**
 * 解析 UCXE 头部 + 载荷。任何非法 / 越界返回 null（折叠为 DecryptionError）。
 * 严格按 UCX-FORMAT §7.2 的字段序与上界。
 */
export function parseUcxe(data: Uint8Array): UcxeHeader | null {
  // 至少需要 8 字节头。
  if (data.length < 8) {
    return null;
  }
  if (!isUcxe(data)) {
    return null;
  }
  const version: number = data[4];
  if (version !== UCXE_FORMAT_VERSION) {
    return null;
  }
  const algorithm: number = data[5];
  const kdfId: number = data[6];
  const flags: number = data[7];
  const tagLen: number = tagLenForAlgo(algorithm);
  if (tagLen < 0) {
    return null;
  }

  const header8: Uint8Array = sliceCopy(data, 0, 8);
  const chunked: boolean = (flags & 0x01) !== 0;

  let o: number = 8;

  // ── KDF 参数块（0 / 4 / 12 字节）─────────────────────────────────────────
  let memoryKib: number = 0;
  let timeCost: number = 0;
  let parallelism: number = 0;
  let iterations: number = 0;
  let kdfRaw: Uint8Array;
  if (kdfId === KDF_NONE) {
    kdfRaw = new Uint8Array(0);
  } else if (kdfId === KDF_ARGON2ID) {
    if (o + 12 > data.length) {
      return null;
    }
    memoryKib = readU32LE(data, o);
    timeCost = readU32LE(data, o + 4);
    parallelism = readU32LE(data, o + 8);
    kdfRaw = sliceCopy(data, o, o + 12);
    o += 12;
  } else if (kdfId === KDF_PBKDF2_HMAC_SHA256) {
    if (o + 4 > data.length) {
      return null;
    }
    iterations = readU32LE(data, o);
    kdfRaw = sliceCopy(data, o, o + 4);
    o += 4;
  } else {
    // 未知 KDF。
    return null;
  }

  // ── salt ─────────────────────────────────────────────────────────────────
  if (o + 2 > data.length) {
    return null;
  }
  const saltLen: number = readU16LE(data, o);
  o += 2;
  if (saltLen > MAX_SALT || o + saltLen > data.length) {
    return null;
  }
  const salt: Uint8Array = sliceCopy(data, o, o + saltLen);
  o += saltLen;

  // ── iv / nonce ─────────────────────────────────────────────────────────────
  if (o + 2 > data.length) {
    return null;
  }
  const ivLen: number = readU16LE(data, o);
  o += 2;
  if (ivLen > MAX_IV || o + ivLen > data.length) {
    return null;
  }
  const iv: Uint8Array = sliceCopy(data, o, o + ivLen);
  o += ivLen;

  // ── ciphertext length (u64 LE) ───────────────────────────────────────────
  if (o + 8 > data.length) {
    return null;
  }
  const ctLen: number = readU64LE(data, o);
  o += 8;
  if (ctLen > MAX_CT || o + ctLen > data.length) {
    return null;
  }
  const ciphertext: Uint8Array = sliceCopy(data, o, o + ctLen);
  o += ctLen;

  // ── tag（算法定长，无长度前缀）───────────────────────────────────────────
  if (o + tagLen > data.length) {
    return null;
  }
  const tag: Uint8Array = sliceCopy(data, o, o + tagLen);

  const kdfParams: KdfParams = new KdfParams(
    kdfId, memoryKib, timeCost, parallelism, iterations, kdfRaw,
  );

  return new UcxeHeader(
    header8, algorithm, kdfId, flags, chunked, kdfParams, salt, iv, ciphertext, tag,
  );
}

/** 构造 AEAD 的 AAD = header(8) ‖ kdf_params ‖ salt（含原始 flags 字节）。 */
function buildAeadAad(h: UcxeHeader): Uint8Array {
  return concatBytes([h.header8, h.kdfParams.rawBytes, h.salt]);
}

/**
 * 用 32 字节直接密钥解密 UCXE（KDF=None）。
 * AES-CBC 在直接密钥模式被拒绝（需 64 字节 enc+mac）。
 * @returns 明文，或 null（任何失败）。
 */
export function decryptWithKey(data: Uint8Array, key: Uint8Array): Uint8Array | null {
  const h: UcxeHeader | null = parseUcxe(data);
  if (h === null) {
    return null;
  }
  // 直接密钥仅允许 KDF=None。
  if (h.kdfId !== KDF_NONE) {
    return null;
  }
  if (key.length !== 32) {
    return null;
  }
  // CBC 直接密钥模式被拒绝。
  if (h.algorithm === ALGO_AES_256_CBC) {
    return null;
  }
  return decryptAead(h, key);
}

/**
 * 用口令解密 UCXE（KDF≠None）。口令在 KDF 内部做 NFC 归一化。
 * @returns 明文，或 null（任何失败）。
 */
export function decryptWithPassphrase(data: Uint8Array, passphrase: string): Uint8Array | null {
  const h: UcxeHeader | null = parseUcxe(data);
  if (h === null) {
    return null;
  }
  if (h.kdfId === KDF_NONE) {
    // 口令模式必须有真实 KDF。
    return null;
  }
  // 解析后、派生前校验 KDF 参数范围。
  if (!validateKdfParams(h.kdfParams)) {
    return null;
  }

  // 派生密钥长度：AEAD=32，AES-CBC=64。
  const isCbc: boolean = h.algorithm === ALGO_AES_256_CBC;
  const dkLen: number = isCbc ? 64 : 32;
  const derived: Uint8Array | null = deriveKeyFromPassphrase(
    h.kdfParams, passphrase, h.salt, dkLen,
  );
  if (derived === null) {
    return null;
  }

  if (isCbc) {
    const encKey: Uint8Array = sliceCopy(derived, 0, 32);
    const macKey: Uint8Array = sliceCopy(derived, 32, 64);
    return aesCbcHmacDecrypt(encKey, macKey, h.iv, h.ciphertext, h.tag, h.header8);
  }
  return decryptAead(h, derived);
}

/**
 * AEAD 解密分派（GCM / ChaCha20），处理分块与非分块两条路径。
 * key 为 32 字节。
 */
function decryptAead(h: UcxeHeader, key: Uint8Array): Uint8Array | null {
  if (h.algorithm !== ALGO_AES_256_GCM && h.algorithm !== ALGO_CHACHA20_POLY1305) {
    return null;
  }
  const aad: Uint8Array = buildAeadAad(h);
  if (h.chunked) {
    return decryptChunked(h, key, aad);
  }
  // 非分块：nonce 12，tag 16。
  if (h.iv.length !== AEAD_NONCE_LEN || h.tag.length !== 16) {
    return null;
  }
  return aeadDecryptOne(h.algorithm, key, h.iv, h.ciphertext, h.tag, aad);
}

/** 调用具体 AEAD 算法解密一段（验证 tag），失败返回 null。 */
function aeadDecryptOne(
  algorithm: number,
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  aad: Uint8Array,
): Uint8Array | null {
  if (algorithm === ALGO_AES_256_GCM) {
    return aesGcmDecrypt(key, nonce, ciphertext, tag, aad);
  }
  if (algorithm === ALGO_CHACHA20_POLY1305) {
    return chacha20Poly1305Decrypt(key, nonce, ciphertext, tag, aad);
  }
  return null;
}

/**
 * 分块 AEAD 解密（UCX-FORMAT §7.7）。
 *
 * 序列化 chunk stream（= 头部 ciphertext 字段）：
 *   [ chunk_count : u32 LE ]
 *   repeat:
 *     [ chunk_ciphertext_size : u32 LE ]
 *     [ ciphertext : size bytes ]   ; 不含 tag
 *     [ tag : 16 bytes ]            ; 每块独立 AEAD tag
 *
 * 每块 nonce = base_nonce[0..8] ‖ u32_be(chunk_index)（拼接，非 XOR）；
 * AAD 与文件级 AAD 相同（每块都用）。任一块失败即整体失败。
 */
function decryptChunked(h: UcxeHeader, key: Uint8Array, aad: Uint8Array): Uint8Array | null {
  // 分块仅支持 AEAD（GCM / ChaCha20）；base nonce 必须 12 字节。
  if (h.iv.length !== AEAD_NONCE_LEN) {
    return null;
  }
  const stream: Uint8Array = h.ciphertext;
  if (stream.length < 4) {
    return null;
  }
  let o: number = 0;
  const chunkCount: number = readU32LE(stream, o);
  o += 4;
  // 防御性上界：chunk 数不超过载荷字节数。
  if (chunkCount > stream.length) {
    return null;
  }

  const parts: Uint8Array[] = [];
  const base: Uint8Array = h.iv;
  for (let i = 0; i < chunkCount; i++) {
    if (o + 4 > stream.length) {
      return null;
    }
    const size: number = readU32LE(stream, o);
    o += 4;
    if (o + size + UCXE_CHUNK_TAG_LEN > stream.length) {
      return null;
    }
    const ct: Uint8Array = sliceCopy(stream, o, o + size);
    o += size;
    const tag: Uint8Array = sliceCopy(stream, o, o + UCXE_CHUNK_TAG_LEN);
    o += UCXE_CHUNK_TAG_LEN;

    // nonce_i = base[0..8] ‖ u32_be(i)。
    const nonce: Uint8Array = new Uint8Array(12);
    nonce.set(base.subarray(0, 8), 0);
    nonce.set(u32be(i), 8);

    const pt: Uint8Array | null = aeadDecryptOne(h.algorithm, key, nonce, ct, tag, aad);
    if (pt === null) {
      return null;
    }
    parts.push(pt);
  }
  // 必须恰好消费完整个 stream（多余字节视为非法）。
  if (o !== stream.length) {
    return null;
  }
  return concatBytes(parts);
}
