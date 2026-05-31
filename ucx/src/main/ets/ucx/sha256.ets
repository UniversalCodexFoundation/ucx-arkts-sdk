/*
 * SPDX-License-Identifier: MIT
 *
 * sha256.ets —— 纯 ArkTS 实现的 SHA-256 与 HMAC-SHA256（FIPS 180-4 / RFC 2104）。
 *
 * 用途：PBKDF2-HMAC-SHA256（KDF）、AES-CBC 的 Encrypt-then-MAC（HMAC-SHA256）。
 * 虽然 @kit.CryptoArchitectureKit 提供 SHA256/HMAC（createMd/createMac），但其 API
 * 为异步（Promise）且部分能力随版本变化；而本 SDK 的 UCXE 解密契约为**同步**接口，
 * 故采用自带纯实现以保证同步、确定、跨版本一致，并便于审阅。已对 NIST 测试向量验证。
 *
 * ArkTS 注意：用 Uint32Array 做 32-bit 运算；移位用 >>> 保持无符号。
 */

const K: Uint32Array = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const H0: Uint32Array = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

/** 32-bit 循环右移。 */
function rotr(x: number, n: number): number {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

/** 计算 SHA-256，返回 32 字节摘要。 */
export function sha256(message: Uint8Array): Uint8Array {
  const ml: number = message.length;
  // padding：消息 + 0x80 + 0x00... 直到长度 ≡ 56 (mod 64)，再加 64-bit 位长。
  const withOne: number = ml + 1;
  const k: number = (56 - (withOne % 64) + 64) % 64;
  const totalLen: number = withOne + k + 8;
  const buf: Uint8Array = new Uint8Array(totalLen);
  buf.set(message, 0);
  buf[ml] = 0x80;
  // 64-bit 大端位长（消息字节数 * 8）。JS number 可安全表示到 2^53。
  const bitLen: number = ml * 8;
  const hi: number = Math.floor(bitLen / 0x100000000);
  const lo: number = bitLen >>> 0;
  buf[totalLen - 8] = (hi >>> 24) & 0xff;
  buf[totalLen - 7] = (hi >>> 16) & 0xff;
  buf[totalLen - 6] = (hi >>> 8) & 0xff;
  buf[totalLen - 5] = hi & 0xff;
  buf[totalLen - 4] = (lo >>> 24) & 0xff;
  buf[totalLen - 3] = (lo >>> 16) & 0xff;
  buf[totalLen - 2] = (lo >>> 8) & 0xff;
  buf[totalLen - 1] = lo & 0xff;

  const h: Uint32Array = new Uint32Array(8);
  for (let i = 0; i < 8; i++) {
    h[i] = H0[i];
  }
  const w: Uint32Array = new Uint32Array(64);

  for (let off = 0; off < totalLen; off += 64) {
    for (let i = 0; i < 16; i++) {
      const j: number = off + i * 4;
      w[i] = ((buf[j] << 24) | (buf[j + 1] << 16) | (buf[j + 2] << 8) | buf[j + 3]) >>> 0;
    }
    for (let i = 16; i < 64; i++) {
      const s0: number =
        (rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3)) >>> 0;
      const s1: number =
        (rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10)) >>> 0;
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let a: number = h[0];
    let b: number = h[1];
    let c: number = h[2];
    let d: number = h[3];
    let e: number = h[4];
    let f: number = h[5];
    let g: number = h[6];
    let hh: number = h[7];

    for (let i = 0; i < 64; i++) {
      const S1: number = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
      const ch: number = ((e & f) ^ (~e & g)) >>> 0;
      const temp1: number = (hh + S1 + ch + K[i] + w[i]) >>> 0;
      const S0: number = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
      const maj: number = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const temp2: number = (S0 + maj) >>> 0;
      hh = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    h[0] = (h[0] + a) >>> 0;
    h[1] = (h[1] + b) >>> 0;
    h[2] = (h[2] + c) >>> 0;
    h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0;
    h[5] = (h[5] + f) >>> 0;
    h[6] = (h[6] + g) >>> 0;
    h[7] = (h[7] + hh) >>> 0;
  }

  const out: Uint8Array = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    const v: number = h[i] >>> 0;
    out[i * 4] = (v >>> 24) & 0xff;
    out[i * 4 + 1] = (v >>> 16) & 0xff;
    out[i * 4 + 2] = (v >>> 8) & 0xff;
    out[i * 4 + 3] = v & 0xff;
  }
  return out;
}

const SHA256_BLOCK: number = 64;

/** 计算 HMAC-SHA256（RFC 2104），返回 32 字节标签。 */
export function hmacSha256(key: Uint8Array, message: Uint8Array): Uint8Array {
  // 若 key 超过块长则先哈希；再补零到块长。
  let k: Uint8Array;
  if (key.length > SHA256_BLOCK) {
    k = sha256(key);
  } else {
    k = key;
  }
  const keyBlock: Uint8Array = new Uint8Array(SHA256_BLOCK);
  keyBlock.set(k, 0);

  const ipad: Uint8Array = new Uint8Array(SHA256_BLOCK);
  const opad: Uint8Array = new Uint8Array(SHA256_BLOCK);
  for (let i = 0; i < SHA256_BLOCK; i++) {
    ipad[i] = keyBlock[i] ^ 0x36;
    opad[i] = keyBlock[i] ^ 0x5c;
  }

  // inner = SHA256(ipad ‖ message)
  const inner: Uint8Array = new Uint8Array(SHA256_BLOCK + message.length);
  inner.set(ipad, 0);
  inner.set(message, SHA256_BLOCK);
  const innerHash: Uint8Array = sha256(inner);

  // outer = SHA256(opad ‖ innerHash)
  const outer: Uint8Array = new Uint8Array(SHA256_BLOCK + 32);
  outer.set(opad, 0);
  outer.set(innerHash, SHA256_BLOCK);
  return sha256(outer);
}
