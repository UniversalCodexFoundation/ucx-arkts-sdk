/*
 * SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * ed25519.ets —— 纯 ArkTS 实现的 Ed25519 签名验证（RFC 8032），含其依赖的 SHA-512。
 *
 * 用途：UCX 双层签名验证（UCX-FORMAT §6）。两层都用 Ed25519 over BLAKE3 摘要，算法 id 0x0001。
 *   - Layer 1：Ed25519 验 {SIGNER}.EC 中的签名 over {SIGNER}.SF 原始字节。
 *   - Layer 2：Ed25519 验签名块里的签名 over signed_data 字节。
 *
 * 为何自带：经调研，HarmonyOS / OpenHarmony 的 @kit.CryptoArchitectureKit **不支持 Ed25519 /
 * EdDSA**（仅 RSA / ECC(ECDSA) / SM2），且其签名 API 为异步。故必须自带纯实现，保证可验签、
 * 同步、跨版本一致、可审阅。已在 scripts/verify-ed25519.cjs 中对 RFC 8032 §7.1 官方测试向量
 * 与真实夹具 sample-signed.ucx 验证（验签通过、指纹匹配）。
 *
 * 实现要点（RFC 8032 Ed25519，verify-only）：
 *   - 域 GF(p)，p = 2^255 - 19。点用扩展坐标（X,Y,Z,T）做加法/倍乘。
 *   - 验证方程：检查 [s]B == R + [k]A（等价地 [8s]B == [8]R + [8k]A，本实现用未乘 8 的标准式，
 *     与 RFC 8032 §5.1.7 的“cofactorless”一致；参考实现 ed25519-dalek 的 verify() 默认也接受）。
 *   - SHA-512 用 64-bit 字（lo/hi 拆分）纯实现。
 *   - 大数运算用 BigInt（ArkTS 支持 BigInt），保证模运算正确、易审阅。
 *
 * ArkTS 注意：禁 any；字段元素用 bigint，字节用 Uint8Array。
 */

import { constantTimeEqual } from './util';

// ── SHA-512（FIPS 180-4），64-bit 字用 lo/hi 拆分 ────────────────────────────

const SHA512_K_HI: Uint32Array = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  0xca273ece, 0xd186b8c7, 0xeada7dd6, 0xf57d4f7f, 0x06f067aa, 0x0a637dc5, 0x113f9804, 0x1b710b35,
  0x28db77f5, 0x32caab7b, 0x3c9ebe0a, 0x431d67c4, 0x4cc5d4be, 0x597f299c, 0x5fcb6fab, 0x6c44198c,
]);
const SHA512_K_LO: Uint32Array = new Uint32Array([
  0xd728ae22, 0x23ef65cd, 0xec4d3b2f, 0x8189dbbc, 0xf348b538, 0xb605d019, 0xaf194f9b, 0xda6d8118,
  0xa3030242, 0x45706fbe, 0x4ee4b28c, 0xd5ffb4e2, 0xf27b896f, 0x3b1696b1, 0x25c71235, 0xcf692694,
  0x9ef14ad2, 0x384f25e3, 0x8b8cd5b5, 0x77ac9c65, 0x592b0275, 0x6ea6e483, 0xbd41fbd4, 0x831153b5,
  0xee66dfab, 0x2db43210, 0x98fb213f, 0xbeef0ee4, 0x3da88fc2, 0x930aa725, 0xe003826f, 0x0a0e6e70,
  0x46d22ffc, 0x5c26c926, 0x5ac42aed, 0x9d95b3df, 0x8baf63de, 0x3c77b2a8, 0x47edaee6, 0x1482353b,
  0x4cf10364, 0xbc423001, 0xd0f89791, 0x0654be30, 0xd6ef5218, 0x5565a910, 0x5771202a, 0x32bbd1b8,
  0xb8d2d0c8, 0x5141ab53, 0xdf8eeb99, 0xe19b48a8, 0xc5c95a63, 0xe3418acb, 0x7763e373, 0xd6b2b8a3,
  0x5defb2fc, 0x43172f60, 0xa1f0ab72, 0x1a6439ec, 0x23631e28, 0xde82bde9, 0xb2c67915, 0xe372532b,
  0xea26619c, 0x21c0c207, 0xcde0eb1e, 0xee6ed178, 0x72176fba, 0xa2c898a6, 0xbef90dae, 0x131c471b,
  0x23047d84, 0x40c72493, 0x15c9bebc, 0x9c100d4c, 0xcb3e42b6, 0xfc657e2a, 0x3ad6faec, 0x4a475817,
]);
const SHA512_H_HI: Uint32Array = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);
const SHA512_H_LO: Uint32Array = new Uint32Array([
  0xf3bcc908, 0x84caa73b, 0xfe94f82b, 0x5f1d36f1, 0xade682d1, 0x2b3e6c1f, 0xfb41bd6b, 0x137e2179,
]);

/** SHA-512，返回 64 字节摘要（用 64-bit lo/hi 运算）。 */
export function sha512(message: Uint8Array): Uint8Array {
  const ml: number = message.length;
  // padding：消息 + 0x80 + 零 + 128-bit 位长，对齐到 128 字节块。
  const withOne: number = ml + 1;
  const k: number = (112 - (withOne % 128) + 128) % 128;
  const totalLen: number = withOne + k + 16;
  const buf: Uint8Array = new Uint8Array(totalLen);
  buf.set(message, 0);
  buf[ml] = 0x80;
  const bitLen: number = ml * 8;
  // 128-bit 位长（高 64 位为 0，低 64 位写 bitLen）。
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

  const hHi: Uint32Array = new Uint32Array(8);
  const hLo: Uint32Array = new Uint32Array(8);
  for (let i = 0; i < 8; i++) {
    hHi[i] = SHA512_H_HI[i];
    hLo[i] = SHA512_H_LO[i];
  }
  const wHi: Uint32Array = new Uint32Array(80);
  const wLo: Uint32Array = new Uint32Array(80);

  for (let off = 0; off < totalLen; off += 128) {
    for (let i = 0; i < 16; i++) {
      const j: number = off + i * 8;
      wHi[i] = ((buf[j] << 24) | (buf[j + 1] << 16) | (buf[j + 2] << 8) | buf[j + 3]) >>> 0;
      wLo[i] = ((buf[j + 4] << 24) | (buf[j + 5] << 16) | (buf[j + 6] << 8) | buf[j + 7]) >>> 0;
    }
    for (let i = 16; i < 80; i++) {
      // s0 = ror(w15,1) ^ ror(w15,8) ^ shr(w15,7)
      const x15Hi: number = wHi[i - 15];
      const x15Lo: number = wLo[i - 15];
      const s0Hi: number = (ror64Hi(x15Hi, x15Lo, 1) ^ ror64Hi(x15Hi, x15Lo, 8) ^ shr64Hi(x15Hi, x15Lo, 7)) >>> 0;
      const s0Lo: number = (ror64Lo(x15Hi, x15Lo, 1) ^ ror64Lo(x15Hi, x15Lo, 8) ^ shr64Lo(x15Hi, x15Lo, 7)) >>> 0;
      // s1 = ror(w2,19) ^ ror(w2,61) ^ shr(w2,6)
      const x2Hi: number = wHi[i - 2];
      const x2Lo: number = wLo[i - 2];
      const s1Hi: number = (ror64Hi(x2Hi, x2Lo, 19) ^ ror64Hi(x2Hi, x2Lo, 61) ^ shr64Hi(x2Hi, x2Lo, 6)) >>> 0;
      const s1Lo: number = (ror64Lo(x2Hi, x2Lo, 19) ^ ror64Lo(x2Hi, x2Lo, 61) ^ shr64Lo(x2Hi, x2Lo, 6)) >>> 0;
      // w[i] = w[i-16] + s0 + w[i-7] + s1
      const r: number[] = add64x4(
        wHi[i - 16], wLo[i - 16], s0Hi, s0Lo, wHi[i - 7], wLo[i - 7], s1Hi, s1Lo,
      );
      wHi[i] = r[0];
      wLo[i] = r[1];
    }

    let aHi: number = hHi[0], aLo: number = hLo[0];
    let bHi: number = hHi[1], bLo: number = hLo[1];
    let cHi: number = hHi[2], cLo: number = hLo[2];
    let dHi: number = hHi[3], dLo: number = hLo[3];
    let eHi: number = hHi[4], eLo: number = hLo[4];
    let fHi: number = hHi[5], fLo: number = hLo[5];
    let gHi: number = hHi[6], gLo: number = hLo[6];
    let hhHi: number = hHi[7], hhLo: number = hLo[7];

    for (let i = 0; i < 80; i++) {
      // S1 = ror(e,14) ^ ror(e,18) ^ ror(e,41)
      const S1Hi: number = (ror64Hi(eHi, eLo, 14) ^ ror64Hi(eHi, eLo, 18) ^ ror64Hi(eHi, eLo, 41)) >>> 0;
      const S1Lo: number = (ror64Lo(eHi, eLo, 14) ^ ror64Lo(eHi, eLo, 18) ^ ror64Lo(eHi, eLo, 41)) >>> 0;
      // ch = (e & f) ^ (~e & g)
      const chHi: number = ((eHi & fHi) ^ (~eHi & gHi)) >>> 0;
      const chLo: number = ((eLo & fLo) ^ (~eLo & gLo)) >>> 0;
      // temp1 = h + S1 + ch + K[i] + w[i]
      const t1: number[] = add64x5(
        hhHi, hhLo, S1Hi, S1Lo, chHi, chLo, SHA512_K_HI[i], SHA512_K_LO[i], wHi[i], wLo[i],
      );
      // S0 = ror(a,28) ^ ror(a,34) ^ ror(a,39)
      const S0Hi: number = (ror64Hi(aHi, aLo, 28) ^ ror64Hi(aHi, aLo, 34) ^ ror64Hi(aHi, aLo, 39)) >>> 0;
      const S0Lo: number = (ror64Lo(aHi, aLo, 28) ^ ror64Lo(aHi, aLo, 34) ^ ror64Lo(aHi, aLo, 39)) >>> 0;
      // maj = (a & b) ^ (a & c) ^ (b & c)
      const majHi: number = ((aHi & bHi) ^ (aHi & cHi) ^ (bHi & cHi)) >>> 0;
      const majLo: number = ((aLo & bLo) ^ (aLo & cLo) ^ (bLo & cLo)) >>> 0;
      const t2: number[] = add64(S0Hi, S0Lo, majHi, majLo);

      hhHi = gHi; hhLo = gLo;
      gHi = fHi; gLo = fLo;
      fHi = eHi; fLo = eLo;
      const eNew: number[] = add64(dHi, dLo, t1[0], t1[1]);
      eHi = eNew[0]; eLo = eNew[1];
      dHi = cHi; dLo = cLo;
      cHi = bHi; cLo = bLo;
      bHi = aHi; bLo = aLo;
      const aNew: number[] = add64(t1[0], t1[1], t2[0], t2[1]);
      aHi = aNew[0]; aLo = aNew[1];
    }

    const u0: number[] = add64(hHi[0], hLo[0], aHi, aLo); hHi[0] = u0[0]; hLo[0] = u0[1];
    const u1: number[] = add64(hHi[1], hLo[1], bHi, bLo); hHi[1] = u1[0]; hLo[1] = u1[1];
    const u2: number[] = add64(hHi[2], hLo[2], cHi, cLo); hHi[2] = u2[0]; hLo[2] = u2[1];
    const u3: number[] = add64(hHi[3], hLo[3], dHi, dLo); hHi[3] = u3[0]; hLo[3] = u3[1];
    const u4: number[] = add64(hHi[4], hLo[4], eHi, eLo); hHi[4] = u4[0]; hLo[4] = u4[1];
    const u5: number[] = add64(hHi[5], hLo[5], fHi, fLo); hHi[5] = u5[0]; hLo[5] = u5[1];
    const u6: number[] = add64(hHi[6], hLo[6], gHi, gLo); hHi[6] = u6[0]; hLo[6] = u6[1];
    const u7: number[] = add64(hHi[7], hLo[7], hhHi, hhLo); hHi[7] = u7[0]; hLo[7] = u7[1];
  }

  const out: Uint8Array = new Uint8Array(64);
  for (let i = 0; i < 8; i++) {
    const vhi: number = hHi[i] >>> 0;
    const vlo: number = hLo[i] >>> 0;
    out[i * 8] = (vhi >>> 24) & 0xff;
    out[i * 8 + 1] = (vhi >>> 16) & 0xff;
    out[i * 8 + 2] = (vhi >>> 8) & 0xff;
    out[i * 8 + 3] = vhi & 0xff;
    out[i * 8 + 4] = (vlo >>> 24) & 0xff;
    out[i * 8 + 5] = (vlo >>> 16) & 0xff;
    out[i * 8 + 6] = (vlo >>> 8) & 0xff;
    out[i * 8 + 7] = vlo & 0xff;
  }
  return out;
}

// 64-bit 操作辅助（hi/lo 各 32-bit）。
function ror64Hi(hi: number, lo: number, n: number): number {
  if (n === 32) return lo >>> 0;
  if (n < 32) return ((hi >>> n) | (lo << (32 - n))) >>> 0;
  const m: number = n - 32;
  return ((lo >>> m) | (hi << (32 - m))) >>> 0;
}
function ror64Lo(hi: number, lo: number, n: number): number {
  if (n === 32) return hi >>> 0;
  if (n < 32) return ((lo >>> n) | (hi << (32 - n))) >>> 0;
  const m: number = n - 32;
  return ((hi >>> m) | (lo << (32 - m))) >>> 0;
}
function shr64Hi(hi: number, lo: number, n: number): number {
  if (n < 32) return (hi >>> n) >>> 0;
  return 0;
}
function shr64Lo(hi: number, lo: number, n: number): number {
  if (n < 32) return ((lo >>> n) | (hi << (32 - n))) >>> 0;
  return (hi >>> (n - 32)) >>> 0;
}
/** 64-bit 加法（hi/lo），返回 [hi,lo]。 */
function add64(aHi: number, aLo: number, bHi: number, bLo: number): number[] {
  const lo: number = (aLo >>> 0) + (bLo >>> 0);
  const carry: number = Math.floor(lo / 0x100000000);
  const hi: number = ((aHi >>> 0) + (bHi >>> 0) + carry) >>> 0;
  return [hi, lo >>> 0];
}
function add64x4(
  h0: number, l0: number, h1: number, l1: number, h2: number, l2: number, h3: number, l3: number,
): number[] {
  let lo: number = (l0 >>> 0) + (l1 >>> 0) + (l2 >>> 0) + (l3 >>> 0);
  const carry: number = Math.floor(lo / 0x100000000);
  const hi: number = ((h0 >>> 0) + (h1 >>> 0) + (h2 >>> 0) + (h3 >>> 0) + carry) >>> 0;
  return [hi, lo >>> 0];
}
function add64x5(
  h0: number, l0: number, h1: number, l1: number, h2: number, l2: number,
  h3: number, l3: number, h4: number, l4: number,
): number[] {
  let lo: number = (l0 >>> 0) + (l1 >>> 0) + (l2 >>> 0) + (l3 >>> 0) + (l4 >>> 0);
  const carry: number = Math.floor(lo / 0x100000000);
  const hi: number = ((h0 >>> 0) + (h1 >>> 0) + (h2 >>> 0) + (h3 >>> 0) + (h4 >>> 0) + carry) >>> 0;
  return [hi, lo >>> 0];
}

// ── Ed25519 字段 / 群运算（用 BigInt）─────────────────────────────────────

/** p = 2^255 - 19。 */
const P: bigint = (1n << 255n) - 19n;
/** 群阶 L = 2^252 + 27742317777372353535851937790883648493。 */
const L: bigint = (1n << 252n) + 27742317777372353535851937790883648493n;
/** d = -121665/121666 mod p。 */
const D: bigint = mod(-121665n * inv(121666n));
/** sqrt(-1) mod p。 */
const SQRT_M1: bigint = powmod(2n, (P - 1n) / 4n, P);

/** 标准模（结果非负）。 */
function mod(a: bigint): bigint {
  let r: bigint = a % P;
  if (r < 0n) {
    r += P;
  }
  return r;
}

/** 模 p 求逆（费马小定理，a^(p-2)）。 */
function inv(a: bigint): bigint {
  return powmod(mod(a), P - 2n, P);
}

/** 模幂 base^exp mod m。 */
function powmod(base: bigint, exp: bigint, m: bigint): bigint {
  let result: bigint = 1n;
  let b: bigint = base % m;
  let e: bigint = exp;
  while (e > 0n) {
    if ((e & 1n) === 1n) {
      result = (result * b) % m;
    }
    b = (b * b) % m;
    e >>= 1n;
  }
  return result;
}

/**
 * Edwards 曲线扩展坐标点 (X, Y, Z, T)，满足 x = X/Z, y = Y/Z, x*y = T/Z。
 * 用类承载，便于点加 / 点倍 / 标量乘。
 */
class Point {
  X: bigint;
  Y: bigint;
  Z: bigint;
  T: bigint;
  constructor(X: bigint, Y: bigint, Z: bigint, T: bigint) {
    this.X = X;
    this.Y = Y;
    this.Z = Z;
    this.T = T;
  }
}

/** 中性元 (0,1)。 */
function identityPoint(): Point {
  return new Point(0n, 1n, 1n, 0n);
}

/** 基点 B。 */
function basePoint(): Point {
  const by: bigint = mod(4n * inv(5n));
  const bx: bigint = recoverX(by, 0n);
  return new Point(bx, by, 1n, mod(bx * by));
}

/** 扩展坐标点加（RFC 8032 §5.1.4 的统一加法公式）。 */
function pointAdd(p1: Point, p2: Point): Point {
  const A: bigint = mod((p1.Y - p1.X) * (p2.Y - p2.X));
  const B: bigint = mod((p1.Y + p1.X) * (p2.Y + p2.X));
  const C: bigint = mod(2n * p1.T * p2.T * D);
  const Dd: bigint = mod(2n * p1.Z * p2.Z);
  const E: bigint = mod(B - A);
  const F: bigint = mod(Dd - C);
  const G: bigint = mod(Dd + C);
  const H: bigint = mod(B + A);
  const X3: bigint = mod(E * F);
  const Y3: bigint = mod(G * H);
  const T3: bigint = mod(E * H);
  const Z3: bigint = mod(F * G);
  return new Point(X3, Y3, Z3, T3);
}

/** 标量乘 [s]P（蒙哥马利阶梯式 double-and-add；s 已约简到 < 2^256）。 */
function scalarMul(s: bigint, p: Point): Point {
  let q: Point = identityPoint();
  let n: bigint = s;
  let base: Point = p;
  while (n > 0n) {
    if ((n & 1n) === 1n) {
      q = pointAdd(q, base);
    }
    base = pointAdd(base, base);
    n >>= 1n;
  }
  return q;
}

/** 由 y 与符号位恢复 x（RFC 8032 §5.1.3 解压）。失败返回 null。 */
function recoverX(y: bigint, sign: bigint): bigint {
  if (y >= P) {
    return -1n;
  }
  const y2: bigint = mod(y * y);
  const u: bigint = mod(y2 - 1n);
  const v: bigint = mod(D * y2 + 1n);
  // x = u * v^3 * (u * v^7)^((p-5)/8)
  const v3: bigint = mod(v * v * v);
  const v7: bigint = mod(v3 * v3 * v);
  let x: bigint = mod(u * v3 * powmod(mod(u * v7), (P - 5n) / 8n, P));
  // 检查 v*x^2 == u（否则乘 sqrt(-1)）。
  const vx2: bigint = mod(v * x * x);
  if (vx2 === mod(-u)) {
    x = mod(x * SQRT_M1);
  } else if (vx2 !== u) {
    return -1n;
  }
  // 调整符号。
  if ((x & 1n) !== sign) {
    x = mod(-x);
  }
  return x;
}

/** 解压 32 字节编码点为 Point；失败返回 null。 */
function decodePoint(bytes: Uint8Array): Point | null {
  if (bytes.length !== 32) {
    return null;
  }
  // 小端 256-bit，最高位是符号位。
  let y: bigint = 0n;
  for (let i = 31; i >= 0; i--) {
    y = (y << 8n) | BigInt(bytes[i]);
  }
  const sign: bigint = (y >> 255n) & 1n;
  y = y & ((1n << 255n) - 1n);
  const x: bigint = recoverX(y, sign);
  if (x < 0n) {
    return null;
  }
  return new Point(x, y, 1n, mod(x * y));
}

/** 把点编码为 32 字节（用于比较 [s]B 与 R + [k]A）。 */
function encodePoint(p: Point): Uint8Array {
  const zInv: bigint = inv(p.Z);
  const x: bigint = mod(p.X * zInv);
  const y: bigint = mod(p.Y * zInv);
  let enc: bigint = y | ((x & 1n) << 255n);
  const out: Uint8Array = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(enc & 0xffn);
    enc >>= 8n;
  }
  return out;
}

/** 小端字节 -> bigint。 */
function leToBigInt(bytes: Uint8Array): bigint {
  let v: bigint = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    v = (v << 8n) | BigInt(bytes[i]);
  }
  return v;
}

/**
 * 验证 Ed25519 签名（RFC 8032 §5.1.7）。
 * @param message 被签名的原始消息字节。
 * @param signature 64 字节签名（R(32) ‖ S(32)）。
 * @param publicKey 32 字节公钥。
 * @returns 验签是否通过。
 */
export function ed25519Verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean {
  if (signature.length !== 64 || publicKey.length !== 32) {
    return false;
  }
  // 解析 R、S。
  const rBytes: Uint8Array = signature.subarray(0, 32);
  const sBytes: Uint8Array = signature.subarray(32, 64);
  const s: bigint = leToBigInt(sBytes);
  // S 必须 < L（拒绝可塑性）。
  if (s >= L) {
    return false;
  }
  // 解压 A（公钥点）与 R。
  const A: Point | null = decodePoint(publicKey);
  if (A === null) {
    return false;
  }
  const R: Point | null = decodePoint(rBytes);
  if (R === null) {
    return false;
  }
  // k = SHA-512(R ‖ A ‖ M) mod L。
  const toHash: Uint8Array = new Uint8Array(64 + message.length);
  toHash.set(rBytes, 0);
  toHash.set(publicKey, 32);
  toHash.set(message, 64);
  const hk: Uint8Array = sha512(toHash);
  const k: bigint = leToBigInt(hk) % L;

  // 检查 [s]B == R + [k]A（编码后逐字节比较）。
  const sB: Point = scalarMul(s, basePoint());
  const kA: Point = scalarMul(k, A);
  const rhs: Point = pointAdd(R, kA);

  // [CT-DIGEST] 使用常量时间比较编码点，防止计时侧信道泄露验签内部状态。
  const lhsEnc: Uint8Array = encodePoint(sB);
  const rhsEnc: Uint8Array = encodePoint(rhs);
  return constantTimeEqual(lhsEnc, rhsEnc);
}
