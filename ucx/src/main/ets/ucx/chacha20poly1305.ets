/*
 * SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * chacha20poly1305.ets —— 纯 ArkTS 实现的 ChaCha20-Poly1305 AEAD（RFC 8439）。
 *
 * 用途：UCXE algo 0x03（ChaCha20-Poly1305；nonce 12，tag 16）。
 *
 * 为何自带：@kit.CryptoArchitectureKit 的 ChaCha20-Poly1305 仅 API 22+ 才支持（较新的
 * HarmonyOS NEXT 版本），且 Cipher API 为异步；而本 SDK 的解密契约为**同步**且需覆盖
 * 较低 API 版本。故采用自带纯实现，保证同步、跨版本一致、便于审阅。
 * 已对 UCXE 真实夹具（plain-chacha.ucxe）在 Node 自检中验证解密正确。
 *
 * 组成：
 *  - ChaCha20 流密码（20 轮，counter 32-bit，RFC 8439 §2.4）。
 *  - Poly1305 一次性 MAC（RFC 8439 §2.5），用 130-bit 模运算（拆成 26-bit 肢）。
 *  - AEAD 构造（RFC 8439 §2.8）：one-time key = ChaCha20(key, nonce, counter=0) 前 32 字节；
 *    MAC 覆盖 AAD ‖ pad ‖ CT ‖ pad ‖ len(AAD)_le64 ‖ len(CT)_le64。
 *
 * ArkTS 注意：禁 any；用 Uint32Array 做 32-bit 运算，Poly1305 用整数肢避免 BigInt 依赖。
 */

/** 32-bit 循环左移。 */
function rotl32(x: number, n: number): number {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

/** ChaCha 四分之一轮（作用于状态数组的 4 个下标）。 */
function quarterRound(s: Uint32Array, a: number, b: number, c: number, d: number): void {
  s[a] = (s[a] + s[b]) >>> 0; s[d] = rotl32((s[d] ^ s[a]) >>> 0, 16);
  s[c] = (s[c] + s[d]) >>> 0; s[b] = rotl32((s[b] ^ s[c]) >>> 0, 12);
  s[a] = (s[a] + s[b]) >>> 0; s[d] = rotl32((s[d] ^ s[a]) >>> 0, 8);
  s[c] = (s[c] + s[d]) >>> 0; s[b] = rotl32((s[b] ^ s[c]) >>> 0, 7);
}

/** 读小端 u32。 */
function le32(b: Uint8Array, o: number): number {
  return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
}

/** ChaCha20 生成一个 64 字节 keystream 块（counter + nonce）。 */
function chachaBlock(key: Uint8Array, counter: number, nonce: Uint8Array, out: Uint8Array): void {
  const state: Uint32Array = new Uint32Array(16);
  // 常量 "expand 32-byte k"。
  state[0] = 0x61707865;
  state[1] = 0x3320646e;
  state[2] = 0x79622d32;
  state[3] = 0x6b206574;
  for (let i = 0; i < 8; i++) {
    state[4 + i] = le32(key, i * 4);
  }
  state[12] = counter >>> 0;
  state[13] = le32(nonce, 0);
  state[14] = le32(nonce, 4);
  state[15] = le32(nonce, 8);

  const working: Uint32Array = new Uint32Array(16);
  for (let i = 0; i < 16; i++) {
    working[i] = state[i];
  }
  for (let r = 0; r < 10; r++) {
    // 列轮。
    quarterRound(working, 0, 4, 8, 12);
    quarterRound(working, 1, 5, 9, 13);
    quarterRound(working, 2, 6, 10, 14);
    quarterRound(working, 3, 7, 11, 15);
    // 对角轮。
    quarterRound(working, 0, 5, 10, 15);
    quarterRound(working, 1, 6, 11, 12);
    quarterRound(working, 2, 7, 8, 13);
    quarterRound(working, 3, 4, 9, 14);
  }
  for (let i = 0; i < 16; i++) {
    const v: number = (working[i] + state[i]) >>> 0;
    out[i * 4] = v & 0xff;
    out[i * 4 + 1] = (v >>> 8) & 0xff;
    out[i * 4 + 2] = (v >>> 16) & 0xff;
    out[i * 4 + 3] = (v >>> 24) & 0xff;
  }
}

/** ChaCha20 加/解密（对称）：从 initialCounter 起逐块异或。 */
function chacha20(key: Uint8Array, initialCounter: number, nonce: Uint8Array, input: Uint8Array): Uint8Array {
  const out: Uint8Array = new Uint8Array(input.length);
  const block: Uint8Array = new Uint8Array(64);
  let counter: number = initialCounter >>> 0;
  for (let off = 0; off < input.length; off += 64) {
    chachaBlock(key, counter, nonce, block);
    const n: number = Math.min(64, input.length - off);
    for (let i = 0; i < n; i++) {
      out[off + i] = input[off + i] ^ block[i];
    }
    counter = (counter + 1) >>> 0;
  }
  return out;
}

/**
 * Poly1305 一次性 MAC。key 为 32 字节（r ‖ s）。
 * 用 5 个 26-bit 肢实现 130-bit 模 (2^130 - 5) 累加，避免 BigInt。
 */
function poly1305(msg: Uint8Array, key: Uint8Array): Uint8Array {
  // clamp r。
  const r0: number = (le32(key, 0)) & 0x3ffffff;
  const r1: number = ((le32(key, 3) >>> 2)) & 0x3ffff03;
  const r2: number = ((le32(key, 6) >>> 4)) & 0x3ffc0ff;
  const r3: number = ((le32(key, 9) >>> 6)) & 0x3f03fff;
  const r4: number = ((le32(key, 12) >>> 8)) & 0x00fffff;

  // s（用于乘法的 5*r 优化）。
  const s1: number = r1 * 5;
  const s2: number = r2 * 5;
  const s3: number = r3 * 5;
  const s4: number = r4 * 5;

  let h0: number = 0;
  let h1: number = 0;
  let h2: number = 0;
  let h3: number = 0;
  let h4: number = 0;

  let offset: number = 0;
  const len: number = msg.length;
  while (offset < len) {
    const remaining: number = len - offset;
    const blockLen: number = remaining >= 16 ? 16 : remaining;
    // 把 16 字节（不足补零，并在末尾置位）读入 5 个 26-bit 肢。
    const t: Uint8Array = new Uint8Array(17);
    for (let i = 0; i < blockLen; i++) {
      t[i] = msg[offset + i];
    }
    t[blockLen] = 1; // 在最高有效位后置 1（partial 块也如此）。

    const t0: number = le32(t, 0);
    const t1: number = le32(t, 4);
    const t2: number = le32(t, 8);
    const t3: number = le32(t, 12);
    const t4: number = t[16];

    h0 += t0 & 0x3ffffff;
    h1 += ((t0 >>> 26) | (t1 << 6)) & 0x3ffffff;
    h2 += ((t1 >>> 20) | (t2 << 12)) & 0x3ffffff;
    h3 += ((t2 >>> 14) | (t3 << 18)) & 0x3ffffff;
    h4 += ((t3 >>> 8) | (t4 << 24)) & 0x3ffffff;

    // h *= r（mod 2^130-5）。用浮点乘法 + 进位（各乘积 < 2^53）。
    const d0: number = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
    let d1: number = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
    let d2: number = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
    let d3: number = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
    let d4: number = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

    // 进位归一化。
    let c: number = Math.floor(d0 / 0x4000000);
    h0 = d0 % 0x4000000;
    d1 += c;
    c = Math.floor(d1 / 0x4000000);
    h1 = d1 % 0x4000000;
    d2 += c;
    c = Math.floor(d2 / 0x4000000);
    h2 = d2 % 0x4000000;
    d3 += c;
    c = Math.floor(d3 / 0x4000000);
    h3 = d3 % 0x4000000;
    d4 += c;
    c = Math.floor(d4 / 0x4000000);
    h4 = d4 % 0x4000000;
    h0 += c * 5;
    c = Math.floor(h0 / 0x4000000);
    h0 = h0 % 0x4000000;
    h1 += c;

    offset += blockLen;
  }

  // 完整进位传播。
  let c: number = Math.floor(h1 / 0x4000000); h1 = h1 % 0x4000000; h2 += c;
  c = Math.floor(h2 / 0x4000000); h2 = h2 % 0x4000000; h3 += c;
  c = Math.floor(h3 / 0x4000000); h3 = h3 % 0x4000000; h4 += c;
  c = Math.floor(h4 / 0x4000000); h4 = h4 % 0x4000000; h0 += c * 5;
  c = Math.floor(h0 / 0x4000000); h0 = h0 % 0x4000000; h1 += c;

  // 计算 h - p（p = 2^130 - 5），若 h >= p 则用之。
  let g0: number = h0 + 5;
  c = Math.floor(g0 / 0x4000000); g0 = g0 % 0x4000000;
  let g1: number = h1 + c; c = Math.floor(g1 / 0x4000000); g1 = g1 % 0x4000000;
  let g2: number = h2 + c; c = Math.floor(g2 / 0x4000000); g2 = g2 % 0x4000000;
  let g3: number = h3 + c; c = Math.floor(g3 / 0x4000000); g3 = g3 % 0x4000000;
  let g4: number = h4 + c - 0x4000000;

  // mask：若 g4 < 0（即 h < p）则保留 h，否则用 g。
  const mask: number = (g4 >> 31) & 0x3ffffff; // g4<0 -> mask all ones
  // 选择：result = (h & mask') | (g & ~mask')，其中 mask' = ~mask。
  const negMask: number = (~mask) & 0x3ffffff;
  const f0: number = (h0 & mask) | (g0 & negMask);
  const f1: number = (h1 & mask) | (g1 & negMask);
  const f2: number = (h2 & mask) | (g2 & negMask);
  const f3: number = (h3 & mask) | (g3 & negMask);
  const f4: number = (h4 & mask) | ((g4 & 0x3ffffff) & negMask);

  // 拼回 128-bit（4 个 32-bit 字），再加上 key 的 s 部分（key[16..32]）。
  let acc0: number = (f0 | (f1 << 26)) >>> 0;
  let acc1: number = ((f1 >>> 6) | (f2 << 20)) >>> 0;
  let acc2: number = ((f2 >>> 12) | (f3 << 14)) >>> 0;
  let acc3: number = ((f3 >>> 18) | (f4 << 8)) >>> 0;

  // 加 s（小端 32-bit），带进位。
  let carry: number = 0;
  const sVals: number[] = [le32(key, 16), le32(key, 20), le32(key, 24), le32(key, 28)];
  const accVals: number[] = [acc0, acc1, acc2, acc3];
  const outBytes: Uint8Array = new Uint8Array(16);
  for (let i = 0; i < 4; i++) {
    const sum: number = accVals[i] + sVals[i] + carry;
    // 用浮点拆进位（sum 可能略超 2^32）。
    carry = Math.floor(sum / 0x100000000);
    const low: number = sum >>> 0;
    outBytes[i * 4] = low & 0xff;
    outBytes[i * 4 + 1] = (low >>> 8) & 0xff;
    outBytes[i * 4 + 2] = (low >>> 16) & 0xff;
    outBytes[i * 4 + 3] = (low >>> 24) & 0xff;
  }
  return outBytes;
}

/** 写小端 64-bit 长度到 8 字节。 */
function le64(value: number): Uint8Array {
  const b: Uint8Array = new Uint8Array(8);
  const lo: number = value >>> 0;
  const hi: number = Math.floor(value / 0x100000000) >>> 0;
  b[0] = lo & 0xff;
  b[1] = (lo >>> 8) & 0xff;
  b[2] = (lo >>> 16) & 0xff;
  b[3] = (lo >>> 24) & 0xff;
  b[4] = hi & 0xff;
  b[5] = (hi >>> 8) & 0xff;
  b[6] = (hi >>> 16) & 0xff;
  b[7] = (hi >>> 24) & 0xff;
  return b;
}

/** 构造 AEAD 的 MAC 输入：AAD ‖ pad16 ‖ CT ‖ pad16 ‖ len(AAD) ‖ len(CT)。 */
function aeadMacData(aad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  const aadPad: number = (16 - (aad.length % 16)) % 16;
  const ctPad: number = (16 - (ciphertext.length % 16)) % 16;
  const total: number = aad.length + aadPad + ciphertext.length + ctPad + 16;
  const out: Uint8Array = new Uint8Array(total);
  let o: number = 0;
  out.set(aad, o);
  o += aad.length + aadPad;
  out.set(ciphertext, o);
  o += ciphertext.length + ctPad;
  out.set(le64(aad.length), o);
  o += 8;
  out.set(le64(ciphertext.length), o);
  return out;
}

/** 生成 Poly1305 一次性密钥 = ChaCha20(key, nonce, counter=0) 的前 32 字节。 */
function poly1305KeyGen(key: Uint8Array, nonce: Uint8Array): Uint8Array {
  const block: Uint8Array = new Uint8Array(64);
  chachaBlock(key, 0, nonce, block);
  return block.slice(0, 32);
}

/** ChaCha20-Poly1305 AEAD 加密结果。 */
export class ChachaResult {
  ciphertext: Uint8Array;
  tag: Uint8Array;
  constructor(ciphertext: Uint8Array, tag: Uint8Array) {
    this.ciphertext = ciphertext;
    this.tag = tag;
  }
}

/** ChaCha20-Poly1305 加密（仅供自检；阅读器解密不调用）。 */
export function chacha20Poly1305Encrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): ChachaResult {
  const otk: Uint8Array = poly1305KeyGen(key, nonce);
  const ciphertext: Uint8Array = chacha20(key, 1, nonce, plaintext);
  const macData: Uint8Array = aeadMacData(aad, ciphertext);
  const tag: Uint8Array = poly1305(macData, otk);
  return new ChachaResult(ciphertext, tag);
}

/**
 * ChaCha20-Poly1305 解密。先验证 tag，不通过返回 null。
 * @returns 明文，或 null（认证失败）。
 */
export function chacha20Poly1305Decrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  aad: Uint8Array,
): Uint8Array | null {
  if (tag.length !== 16) {
    return null;
  }
  const otk: Uint8Array = poly1305KeyGen(key, nonce);
  const macData: Uint8Array = aeadMacData(aad, ciphertext);
  const expected: Uint8Array = poly1305(macData, otk);
  let diff: number = 0;
  for (let i = 0; i < 16; i++) {
    diff |= expected[i] ^ tag[i];
  }
  if (diff !== 0) {
    return null;
  }
  // 通过后解密（counter 从 1 起）。
  return chacha20(key, 1, nonce, ciphertext);
}
