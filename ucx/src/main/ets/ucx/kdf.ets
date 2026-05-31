/*
 * SPDX-License-Identifier: MIT
 *
 * kdf.ets —— KDF 调度（Key Derivation Function dispatch），对应 UCX-FORMAT §7.4 / §8。
 *
 * 三种 KDF：
 *   - None（0x00）：密钥直接给出（32 字节），不经 KDF。
 *   - Argon2id（0x01）：参数 mem_kib / time / parallelism，输出 32 或 64 字节。
 *   - PBKDF2-HMAC-SHA256（0x02）：参数 iterations，输出 32 或 64 字节。
 *
 * 口令处理（load-bearing）：口令必须先做 **Unicode NFC 归一化**，再转 UTF-8 字节喂入 KDF
 * （UCX-FORMAT §7.8）。否则带组合字符的口令会派生出不同密钥。salt 解密路径要求恰好 16 字节。
 *
 * 参数边界校验（UCX-FORMAT §8）：解析后、派生前必须验证 KDF 参数在允许范围内，越界即拒绝
 * （折叠为 DecryptionError）。本文件提供校验函数；越界返回 null。
 *
 * ArkTS 注意：禁 any；复用 argon2.ets / pbkdf2.ets 的纯实现。NFC 用 String.normalize('NFC')。
 */

import { argon2id, Argon2Params } from './argon2';
import { pbkdf2Sha256 } from './pbkdf2';
import { utf8Encode } from './util';
import {
  KDF_NONE, KDF_ARGON2ID, KDF_PBKDF2_HMAC_SHA256,
  ARGON2_MIN_MEM_KIB, ARGON2_MAX_MEM_KIB, ARGON2_MIN_TIME, ARGON2_MAX_TIME,
  ARGON2_MIN_PARALLELISM, ARGON2_MAX_PARALLELISM,
  PBKDF2_MIN_ITERS, PBKDF2_MAX_ITERS, SALT_LEN,
} from './constants';

/** 解析后的 KDF 参数（按 KDF id 不同携带不同字段）。 */
export class KdfParams {
  /** KDF id（KDF_NONE / KDF_ARGON2ID / KDF_PBKDF2_HMAC_SHA256）。 */
  kdfId: number;
  /** Argon2id 内存代价（KiB）；仅 Argon2id 有意义。 */
  memoryKib: number;
  /** Argon2id 时间代价；仅 Argon2id 有意义。 */
  timeCost: number;
  /** Argon2id 并行度；仅 Argon2id 有意义。 */
  parallelism: number;
  /** PBKDF2 迭代次数；仅 PBKDF2 有意义。 */
  iterations: number;
  /** 该 KDF 参数块在磁盘上的原始 LE 字节（0 / 4 / 12 字节），用于 AEAD AAD 构造。 */
  rawBytes: Uint8Array;

  constructor(
    kdfId: number, memoryKib: number, timeCost: number, parallelism: number,
    iterations: number, rawBytes: Uint8Array,
  ) {
    this.kdfId = kdfId;
    this.memoryKib = memoryKib;
    this.timeCost = timeCost;
    this.parallelism = parallelism;
    this.iterations = iterations;
    this.rawBytes = rawBytes;
  }
}

/**
 * 校验 KDF 参数是否在 UCX-FORMAT §8 允许范围内。
 * @returns true 合法；false 越界（上层折叠为 DecryptionError）。
 */
export function validateKdfParams(params: KdfParams): boolean {
  if (params.kdfId === KDF_NONE) {
    return true;
  }
  if (params.kdfId === KDF_ARGON2ID) {
    if (params.memoryKib < ARGON2_MIN_MEM_KIB || params.memoryKib > ARGON2_MAX_MEM_KIB) {
      return false;
    }
    if (params.timeCost < ARGON2_MIN_TIME || params.timeCost > ARGON2_MAX_TIME) {
      return false;
    }
    if (params.parallelism < ARGON2_MIN_PARALLELISM) {
      return false;
    }
    // [ARGON2-BOUND] parallelism 上限为 255（参考 Argon2 C 库的 uint8 限制），
    // 同时也是移动端内存安全的合理上界。
    if (params.parallelism > ARGON2_MAX_PARALLELISM) {
      return false;
    }
    return true;
  }
  if (params.kdfId === KDF_PBKDF2_HMAC_SHA256) {
    if (params.iterations < PBKDF2_MIN_ITERS || params.iterations > PBKDF2_MAX_ITERS) {
      return false;
    }
    return true;
  }
  // 未知 KDF。
  return false;
}

/**
 * 把口令字符串做 NFC 归一化并转 UTF-8 字节。
 * NFC 归一化是 load-bearing：必须与参考实现一致，否则带组合字符的口令派生出不同密钥。
 */
export function normalizePassphrase(passphrase: string): Uint8Array {
  // String.prototype.normalize 在 ArkTS / 标准 ECMAScript 中可用。
  const nfc: string = passphrase.normalize('NFC');
  return utf8Encode(nfc);
}

/**
 * 由口令派生密钥（Argon2id / PBKDF2）。
 *
 * @param params 已校验的 KDF 参数（kdfId 必须是 Argon2id 或 PBKDF2）。
 * @param passphrase 原始口令字符串（本函数内部做 NFC 归一化）。
 * @param salt 盐（解密路径要求恰好 16 字节）。
 * @param dkLen 派生密钥长度（AEAD=32，AES-CBC=64）。
 * @returns 派生密钥；参数非法或 salt 长度错误返回 null。
 */
export function deriveKeyFromPassphrase(
  params: KdfParams,
  passphrase: string,
  salt: Uint8Array,
  dkLen: number,
): Uint8Array | null {
  // [SALT-VALIDATE] 验证实际 salt 长度与协议规定的 SALT_LEN (16) 一致，
  // 防止头部篡改后传入非标准长度的 salt 导致密钥派生结果不可预测。
  if (salt.length !== SALT_LEN) {
    return null;
  }
  if (passphrase.length === 0) {
    // 空口令被拒绝（UCX-FORMAT §8.3）。
    return null;
  }
  const pw: Uint8Array = normalizePassphrase(passphrase);
  if (pw.length === 0) {
    return null;
  }

  if (params.kdfId === KDF_ARGON2ID) {
    const a2: Argon2Params = new Argon2Params(
      params.memoryKib, params.timeCost, params.parallelism, dkLen,
    );
    return argon2id(pw, salt, a2);
  }
  if (params.kdfId === KDF_PBKDF2_HMAC_SHA256) {
    return pbkdf2Sha256(pw, salt, params.iterations, dkLen);
  }
  return null;
}
