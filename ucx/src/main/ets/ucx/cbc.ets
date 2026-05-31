/*
 * SPDX-License-Identifier: MIT
 *
 * cbc.ets —— AES-256-CBC + HMAC-SHA256（Encrypt-then-MAC, EtM）+ PKCS#7 解密。
 *
 * 用途：UCXE algo 0x02（AES-256-CBC）。该模式不是 AEAD，UCX 用 Encrypt-then-MAC：
 *   - 加密密钥 enc_key = derived[0..32]，MAC 密钥 mac_key = derived[32..64]（共 64 字节）。
 *   - 认证标签 = HMAC-SHA256( aad ‖ iv ‖ ciphertext )，其中 **aad = header(8) 字节**
 *     （注意：CBC 的 HMAC AAD 只是 8 字节头，**不含** KDF params/salt；这与 AEAD 的
 *     AAD 构造不同，见 UCX-FORMAT §7.6，极易混淆）。
 *   - 解密顺序：先**常量时间**校验 HMAC，再 AES-CBC 解密 + PKCS#7 去填充。
 *
 * 安全要求：任何失败（HMAC 不符 / padding 非法 / 长度非法）都返回 null，由上层折叠为
 * 单一不透明 DecryptionError，避免 padding/auth oracle。
 *
 * 直接密钥模式（KDF=None）下 CBC 被拒绝（缺少 64 字节 enc+mac），该判断在 ucxe.ets。
 *
 * ArkTS 注意：禁 any；复用 aes.ets 的 aesCbcDecrypt（raw 块）与 sha256.ets 的 hmacSha256。
 */

import { aesCbcDecrypt } from './aes';
import { hmacSha256 } from './sha256';
import { constantTimeEqual, concatBytes } from './util';
import { CBC_IV_LEN, CBC_MAC_LEN } from './constants';

/**
 * 验证 HMAC 并解密 AES-256-CBC 密文（EtM + PKCS#7）。
 *
 * @param encKey 加密密钥（32 字节，= derived[0..32]）。
 * @param macKey MAC 密钥（32 字节，= derived[32..64]）。
 * @param iv 初始化向量（16 字节）。
 * @param ciphertext 密文（16 的倍数）。
 * @param tag 存储的 HMAC-SHA256 标签（32 字节）。
 * @param headerAad 8 字节 UCXE 头（HMAC 的 AAD；不含 KDF params/salt）。
 * @returns 去填充后的明文，或 null（认证 / padding / 长度失败）。
 */
export function aesCbcHmacDecrypt(
  encKey: Uint8Array,
  macKey: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  headerAad: Uint8Array,
): Uint8Array | null {
  // 基本长度校验。
  if (iv.length !== CBC_IV_LEN || tag.length !== CBC_MAC_LEN) {
    return null;
  }
  if (ciphertext.length === 0 || ciphertext.length % 16 !== 0) {
    return null;
  }

  // 1) 先验证 HMAC-SHA256( header(8) ‖ iv ‖ ciphertext )，常量时间比较。
  const macData: Uint8Array = concatBytes([headerAad, iv, ciphertext]);
  const expected: Uint8Array = hmacSha256(macKey, macData);
  if (!constantTimeEqual(expected, tag)) {
    return null;
  }

  // 2) AES-CBC 解密（raw 块，无 padding 处理）。
  let padded: Uint8Array;
  try {
    padded = aesCbcDecrypt(encKey, iv, ciphertext);
  } catch (e) {
    return null;
  }

  // 3) PKCS#7 去填充（严格校验所有 padding 字节，避免可被探测的歧义）。
  const unpadded: Uint8Array | null = pkcs7Unpad(padded);
  return unpadded;
}

/**
 * PKCS#7 去填充（常量时间验证）。
 * 最后一个字节 n（1..16）给出 padding 长度；末尾 n 个字节都必须等于 n。
 * 任何不符返回 null。
 *
 * [P2 constant-time-unpad] 使用常量时间逻辑验证 padding 字节，
 * 不在循环中提前返回。虽然 HMAC 验证在 CBC 解密前已以常量时间完成
 *（攻击者无法触达 padding 校验），但作为纵深防御仍改为常量时间。
 */
function pkcs7Unpad(data: Uint8Array): Uint8Array | null {
  const len: number = data.length;
  if (len === 0 || len % 16 !== 0) {
    return null;
  }
  const pad: number = data[len - 1];
  if (pad < 1 || pad > 16 || pad > len) {
    return null;
  }
  // 常量时间校验所有填充字节是否等于 pad。
  let diff: number = 0;
  for (let i = len - pad; i < len; i++) {
    diff |= data[i] ^ pad;
  }
  if (diff !== 0) {
    return null;
  }
  const out: Uint8Array = new Uint8Array(len - pad);
  out.set(data.subarray(0, len - pad));
  return out;
}
