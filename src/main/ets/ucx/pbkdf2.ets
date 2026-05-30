/*
 * SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * pbkdf2.ets —— 纯 ArkTS 实现的 PBKDF2-HMAC-SHA256（RFC 2898 / RFC 8018）。
 *
 * 用途：UCXE 口令模式 KDF=PBKDF2（§7.4/§8.2）。默认迭代 600000。
 * 采用自带 hmacSha256（同步、确定），与 SDK 同步解密契约一致。
 * 已对 RFC 6070 风格测试向量验证。
 *
 * 注意：UCX 的口令在进入 KDF 前必须先做 NFC 归一化并转 UTF-8 字节（在 ucxe.ets 中完成）。
 *
 * ArkTS 注意：禁 any；显式类型。
 */

import { hmacSha256 } from './sha256';
import { u32be } from './util';

/**
 * PBKDF2-HMAC-SHA256。
 * @param password 已归一化的口令 UTF-8 字节。
 * @param salt 盐（16 字节）。
 * @param iterations 迭代次数。
 * @param dkLen 派生密钥长度（字节）：AEAD=32，AES-CBC=64。
 */
export function pbkdf2Sha256(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  dkLen: number,
): Uint8Array {
  const hLen: number = 32; // HMAC-SHA256 输出长度
  const blockCount: number = Math.ceil(dkLen / hLen);
  const out: Uint8Array = new Uint8Array(blockCount * hLen);

  for (let block = 1; block <= blockCount; block++) {
    // U1 = HMAC(password, salt ‖ INT_32_BE(block))
    const blockIndex: Uint8Array = u32be(block);
    const saltBlock: Uint8Array = new Uint8Array(salt.length + 4);
    saltBlock.set(salt, 0);
    saltBlock.set(blockIndex, salt.length);

    let u: Uint8Array = hmacSha256(password, saltBlock);
    const t: Uint8Array = new Uint8Array(hLen);
    t.set(u, 0);

    // U2..Uc，逐轮 XOR 累加进 T。
    for (let iter = 1; iter < iterations; iter++) {
      u = hmacSha256(password, u);
      for (let i = 0; i < hLen; i++) {
        t[i] = t[i] ^ u[i];
      }
    }
    out.set(t, (block - 1) * hLen);
  }

  return out.slice(0, dkLen);
}
