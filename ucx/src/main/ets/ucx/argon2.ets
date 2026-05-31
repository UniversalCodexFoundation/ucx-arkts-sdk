/*
 * SPDX-License-Identifier: MIT
 *
 * argon2.ets —— 纯 ArkTS 实现的 Argon2id（RFC 9106），含其依赖的 BLAKE2b。
 *
 * 用途：UCXE 口令模式 KDF=Argon2id（UCX-FORMAT §7.4 / §8.1）。
 *   - 变体：Argon2id（type = 2）。
 *   - 版本：0x13（v19）。
 *   - 默认参数：memory = 65536 KiB（64 MiB），time = 3，parallelism = 4。
 *   - 输出长度：AEAD = 32 字节，AES-CBC = 64 字节。
 *
 * 为何自带：HarmonyOS / OpenHarmony 的 @kit.CryptoArchitectureKit 不提供 Argon2
 * （仅 PBKDF2 等），且其所有 KDF API 为异步；而本 SDK 的 UCXE 解密契约为**同步**接口。
 * 故必须自带纯实现，保证同步、确定、跨版本一致并便于审阅。Argon2 内部用到的 BLAKE2b
 * 也在本文件实现（与 blake3.ets 的 BLAKE3 是不同算法，不可混用）。
 *
 * 算法忠实移植 RFC 9106 参考描述：
 *   1. H0 = BLAKE2b-512( LE32(p) ‖ LE32(τ) ‖ LE32(m) ‖ LE32(t) ‖ LE32(v) ‖ LE32(y)
 *                        ‖ LE32(|P|) ‖ P ‖ LE32(|S|) ‖ S ‖ LE32(|K|) ‖ K
 *                        ‖ LE32(|X|) ‖ X )（K、X 为空）。
 *   2. 内存矩阵 B[lane][col]（每块 1024 字节）按 pass/slice/segment 填充。
 *   3. 块索引 J1/J2 决定引用块；压缩函数 G 基于 BLAKE2b 的 permutation（Argon2 专用 P 变换）。
 *   4. 最终把每 lane 末块异或，再 H'（变长 BLAKE2b）扩展到 τ 字节。
 *
 * 性能说明：m=64 MiB、t=3、p=4 的纯 JS 实现较慢（数秒量级），但解密一次性调用可接受。
 * 正确性已在 scripts/verify-argon2.cjs 中对官方 RFC 9106 测试向量与真实夹具
 * plain-pass.ucxe 验证（派生 32 字节密钥后 AES-GCM 解出 45 字节明文）。
 *
 * ArkTS 注意：禁 any；64-bit 字用「lo/hi 两个 32-bit number」表示，避免 BigInt 依赖。
 */

// ── BLAKE2b（RFC 7693），64-bit 字用 lo/hi 拆分 ─────────────────────────────

/** BLAKE2b 初始向量（8 个 64-bit，按 lo/hi 拆分存放）。 */
const BLAKE2B_IV_LO: Uint32Array = new Uint32Array([
  0xf3bcc908, 0x84caa73b, 0xfe94f82b, 0x5f1d36f1,
  0xade682d1, 0x2b3e6c1f, 0xfb41bd6b, 0x137e2179,
]);
const BLAKE2B_IV_HI: Uint32Array = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

/** BLAKE2b 的消息字调度表（12 轮，每轮 16 个下标）。 */
const BLAKE2B_SIGMA: number[][] = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/**
 * BLAKE2b 上下文（增量哈希）。
 * 状态 h[0..7]、消息块缓冲、已处理字节计数 t（lo/hi）。
 * 64-bit 字一律用并列的两个 Uint32Array（lo / hi）表达。
 */
class Blake2b {
  private hLo: Uint32Array;
  private hHi: Uint32Array;
  private buf: Uint8Array;
  private bufLen: number;
  private tLo: number;
  private tHi: number;
  private outLen: number;

  constructor(outLen: number) {
    this.outLen = outLen;
    this.hLo = new Uint32Array(8);
    this.hHi = new Uint32Array(8);
    for (let i = 0; i < 8; i++) {
      this.hLo[i] = BLAKE2B_IV_LO[i];
      this.hHi[i] = BLAKE2B_IV_HI[i];
    }
    // 参数块：digest_length ‖ key_length(0) ‖ fanout(1) ‖ depth(1)。
    // h[0] ^= 0x0101_0000 | outLen（低 32 位）。
    this.hLo[0] ^= 0x01010000 ^ outLen;
    this.buf = new Uint8Array(128);
    this.bufLen = 0;
    this.tLo = 0;
    this.tHi = 0;
  }

  /** 增量喂入数据。 */
  update(data: Uint8Array): void {
    let off: number = 0;
    const len: number = data.length;
    while (off < len) {
      if (this.bufLen === 128) {
        this.incCounter(128);
        this.compress(false);
        this.bufLen = 0;
      }
      const space: number = 128 - this.bufLen;
      const take: number = Math.min(space, len - off);
      this.buf.set(data.subarray(off, off + take), this.bufLen);
      this.bufLen += take;
      off += take;
    }
  }

  /** 收尾并输出 outLen 字节。 */
  digest(): Uint8Array {
    this.incCounter(this.bufLen);
    // 末块右侧补零。
    for (let i = this.bufLen; i < 128; i++) {
      this.buf[i] = 0;
    }
    this.compress(true);
    const out: Uint8Array = new Uint8Array(this.outLen);
    for (let i = 0; i < this.outLen; i++) {
      const word: number = i >> 3;
      const byteInWord: number = i & 7;
      const v: number = byteInWord < 4
        ? (this.hLo[word] >>> (byteInWord * 8))
        : (this.hHi[word] >>> ((byteInWord - 4) * 8));
      out[i] = v & 0xff;
    }
    return out;
  }

  /** t += n（128-bit 计数器，这里只用低 64 位足够）。 */
  private incCounter(n: number): void {
    const lo: number = (this.tLo + n) >>> 0;
    if (lo < this.tLo) {
      this.tHi = (this.tHi + 1) >>> 0;
    }
    this.tLo = lo;
  }

  /** 压缩当前 128 字节块；last 表示末块（置 f0 = 全 1）。 */
  private compress(last: boolean): void {
    const vLo: Uint32Array = new Uint32Array(16);
    const vHi: Uint32Array = new Uint32Array(16);
    for (let i = 0; i < 8; i++) {
      vLo[i] = this.hLo[i];
      vHi[i] = this.hHi[i];
      vLo[i + 8] = BLAKE2B_IV_LO[i];
      vHi[i + 8] = BLAKE2B_IV_HI[i];
    }
    vLo[12] ^= this.tLo;
    vHi[12] ^= this.tHi;
    // t 高 64 位为 0，不影响 v[13]。
    if (last) {
      vLo[14] ^= 0xffffffff;
      vHi[14] ^= 0xffffffff;
    }

    // 把 128 字节块解析为 16 个 64-bit 小端字（lo/hi）。
    const mLo: Uint32Array = new Uint32Array(16);
    const mHi: Uint32Array = new Uint32Array(16);
    for (let i = 0; i < 16; i++) {
      const j: number = i * 8;
      mLo[i] = (this.buf[j] | (this.buf[j + 1] << 8) | (this.buf[j + 2] << 16) | (this.buf[j + 3] << 24)) >>> 0;
      mHi[i] = (this.buf[j + 4] | (this.buf[j + 5] << 8) | (this.buf[j + 6] << 16) | (this.buf[j + 7] << 24)) >>> 0;
    }

    for (let r = 0; r < 12; r++) {
      const s: number[] = BLAKE2B_SIGMA[r];
      this.mix(vLo, vHi, 0, 4, 8, 12, mLo[s[0]], mHi[s[0]], mLo[s[1]], mHi[s[1]]);
      this.mix(vLo, vHi, 1, 5, 9, 13, mLo[s[2]], mHi[s[2]], mLo[s[3]], mHi[s[3]]);
      this.mix(vLo, vHi, 2, 6, 10, 14, mLo[s[4]], mHi[s[4]], mLo[s[5]], mHi[s[5]]);
      this.mix(vLo, vHi, 3, 7, 11, 15, mLo[s[6]], mHi[s[6]], mLo[s[7]], mHi[s[7]]);
      this.mix(vLo, vHi, 0, 5, 10, 15, mLo[s[8]], mHi[s[8]], mLo[s[9]], mHi[s[9]]);
      this.mix(vLo, vHi, 1, 6, 11, 12, mLo[s[10]], mHi[s[10]], mLo[s[11]], mHi[s[11]]);
      this.mix(vLo, vHi, 2, 7, 8, 13, mLo[s[12]], mHi[s[12]], mLo[s[13]], mHi[s[13]]);
      this.mix(vLo, vHi, 3, 4, 9, 14, mLo[s[14]], mHi[s[14]], mLo[s[15]], mHi[s[15]]);
    }

    for (let i = 0; i < 8; i++) {
      this.hLo[i] ^= vLo[i] ^ vLo[i + 8];
      this.hHi[i] ^= vHi[i] ^ vHi[i + 8];
    }
  }

  /** BLAKE2b 的 G 混合函数（作用于 v 的四个 64-bit 下标）。 */
  private mix(
    vLo: Uint32Array, vHi: Uint32Array,
    a: number, b: number, c: number, d: number,
    xLo: number, xHi: number, yLo: number, yHi: number,
  ): void {
    // a = a + b + x
    add64(vLo, vHi, a, vLo[b], vHi[b]);
    add64(vLo, vHi, a, xLo, xHi);
    // d = rotr64(d ^ a, 32)
    xorRotr(vLo, vHi, d, a, 32);
    // c = c + d
    add64(vLo, vHi, c, vLo[d], vHi[d]);
    // b = rotr64(b ^ c, 24)
    xorRotr(vLo, vHi, b, c, 24);
    // a = a + b + y
    add64(vLo, vHi, a, vLo[b], vHi[b]);
    add64(vLo, vHi, a, yLo, yHi);
    // d = rotr64(d ^ a, 16)
    xorRotr(vLo, vHi, d, a, 16);
    // c = c + d
    add64(vLo, vHi, c, vLo[d], vHi[d]);
    // b = rotr64(b ^ c, 63)
    xorRotr(vLo, vHi, b, c, 63);
  }
}

/** v[idx] += (addLo,addHi)（64-bit 加，进位处理）。 */
function add64(vLo: Uint32Array, vHi: Uint32Array, idx: number, addLo: number, addHi: number): void {
  const lo: number = (vLo[idx] + addLo) >>> 0;
  // 进位：若结果 lo 小于任一加数（无符号）则进 1。
  const carry: number = (lo < (vLo[idx] >>> 0)) ? 1 : 0;
  vLo[idx] = lo;
  vHi[idx] = (vHi[idx] + addHi + carry) >>> 0;
}

/** v[dst] = rotr64(v[dst] ^ v[src], n)。 */
function xorRotr(vLo: Uint32Array, vHi: Uint32Array, dst: number, src: number, n: number): void {
  let lo: number = (vLo[dst] ^ vLo[src]) >>> 0;
  let hi: number = (vHi[dst] ^ vHi[src]) >>> 0;
  const rLo: number = rotr64Lo(lo, hi, n);
  const rHi: number = rotr64Hi(lo, hi, n);
  vLo[dst] = rLo;
  vHi[dst] = rHi;
}

/** 64-bit 循环右移的低 32 位。 */
function rotr64Lo(lo: number, hi: number, n: number): number {
  if (n === 32) {
    return hi >>> 0;
  }
  if (n < 32) {
    return ((lo >>> n) | (hi << (32 - n))) >>> 0;
  }
  const m: number = n - 32;
  return ((hi >>> m) | (lo << (32 - m))) >>> 0;
}

/** 64-bit 循环右移的高 32 位。 */
function rotr64Hi(lo: number, hi: number, n: number): number {
  if (n === 32) {
    return lo >>> 0;
  }
  if (n < 32) {
    return ((hi >>> n) | (lo << (32 - n))) >>> 0;
  }
  const m: number = n - 32;
  return ((lo >>> m) | (hi << (32 - m))) >>> 0;
}

/** 一次性计算 BLAKE2b（outLen ≤ 64 字节）。 */
function blake2b(input: Uint8Array, outLen: number): Uint8Array {
  const h: Blake2b = new Blake2b(outLen);
  h.update(input);
  return h.digest();
}

/** 写小端 u32 到字节数组（Argon2 H0 前缀用）。 */
function le32Bytes(n: number): Uint8Array {
  const b: Uint8Array = new Uint8Array(4);
  b[0] = n & 0xff;
  b[1] = (n >>> 8) & 0xff;
  b[2] = (n >>> 16) & 0xff;
  b[3] = (n >>> 24) & 0xff;
  return b;
}

/**
 * Argon2 的变长哈希 H'（RFC 9106 §3.2）。
 * 若 outLen ≤ 64 直接 BLAKE2b(LE32(outLen) ‖ input)；
 * 否则迭代：V1 = BLAKE2b-64(LE32(outLen) ‖ input)，Vi+1 = BLAKE2b-64(Vi)，
 * 取每个 Vi 的前 32 字节拼接，末块取 BLAKE2b 输出 r 字节（r = outLen-32*(t-1)）。
 */
function argon2Hprime(input: Uint8Array, outLen: number): Uint8Array {
  const prefix: Uint8Array = le32Bytes(outLen);
  const full: Uint8Array = new Uint8Array(prefix.length + input.length);
  full.set(prefix, 0);
  full.set(input, prefix.length);

  if (outLen <= 64) {
    return blake2b(full, outLen);
  }

  const out: Uint8Array = new Uint8Array(outLen);
  let v: Uint8Array = blake2b(full, 64);
  out.set(v.subarray(0, 32), 0);
  let pos: number = 32;
  let remaining: number = outLen - 32;
  while (remaining > 64) {
    v = blake2b(v, 64);
    out.set(v.subarray(0, 32), pos);
    pos += 32;
    remaining -= 32;
  }
  // 末块：r = remaining 字节。
  v = blake2b(v, remaining);
  out.set(v.subarray(0, remaining), pos);
  return out;
}

// ── Argon2 内存填充 ───────────────────────────────────────────────────────────

const ARGON2_BLOCK_SIZE: number = 1024; // 字节
const ARGON2_QWORDS: number = 128; // 每块 128 个 64-bit 字
const ARGON2_TYPE_ID: number = 2; // Argon2id
const ARGON2_SYNC_POINTS: number = 4; // 每 pass 4 个 slice

/**
 * 一个 1024 字节 Argon2 块，用 lo/hi 两个 128 长度的 Uint32Array 表示 128 个 64-bit 字。
 * 用类承载便于在内存矩阵中按引用传递与原地异或。
 */
class Argon2Block {
  lo: Uint32Array;
  hi: Uint32Array;
  constructor() {
    this.lo = new Uint32Array(ARGON2_QWORDS);
    this.hi = new Uint32Array(ARGON2_QWORDS);
  }
  /** 从 1024 字节装载。 */
  fromBytes(bytes: Uint8Array): void {
    for (let i = 0; i < ARGON2_QWORDS; i++) {
      const j: number = i * 8;
      this.lo[i] = (bytes[j] | (bytes[j + 1] << 8) | (bytes[j + 2] << 16) | (bytes[j + 3] << 24)) >>> 0;
      this.hi[i] = (bytes[j + 4] | (bytes[j + 5] << 8) | (bytes[j + 6] << 16) | (bytes[j + 7] << 24)) >>> 0;
    }
  }
  /** 序列化为 1024 字节。 */
  toBytes(): Uint8Array {
    const out: Uint8Array = new Uint8Array(ARGON2_BLOCK_SIZE);
    for (let i = 0; i < ARGON2_QWORDS; i++) {
      const j: number = i * 8;
      out[j] = this.lo[i] & 0xff;
      out[j + 1] = (this.lo[i] >>> 8) & 0xff;
      out[j + 2] = (this.lo[i] >>> 16) & 0xff;
      out[j + 3] = (this.lo[i] >>> 24) & 0xff;
      out[j + 4] = this.hi[i] & 0xff;
      out[j + 5] = (this.hi[i] >>> 8) & 0xff;
      out[j + 6] = (this.hi[i] >>> 16) & 0xff;
      out[j + 7] = (this.hi[i] >>> 24) & 0xff;
    }
    return out;
  }
  /** this = src 的拷贝。 */
  copyFrom(src: Argon2Block): void {
    this.lo.set(src.lo);
    this.hi.set(src.hi);
  }
  /** this ^= other。 */
  xorWith(other: Argon2Block): void {
    for (let i = 0; i < ARGON2_QWORDS; i++) {
      this.lo[i] ^= other.lo[i];
      this.hi[i] ^= other.hi[i];
    }
  }
}

/**
 * Argon2 的 P 置换（基于 BLAKE2b round function，作用于 16 个 64-bit 字）。
 * 对 lo/hi 数组中 16 个连续下标（从 base 起）原地变换。
 */
function argon2Permutation(lo: Uint32Array, hi: Uint32Array, base: number): void {
  // 16 字按 RFC 9106 的 GB/P 结构：先 8 列再 8 对角，G 用专用 64-bit 公式。
  blamkaG(lo, hi, base + 0, base + 4, base + 8, base + 12);
  blamkaG(lo, hi, base + 1, base + 5, base + 9, base + 13);
  blamkaG(lo, hi, base + 2, base + 6, base + 10, base + 14);
  blamkaG(lo, hi, base + 3, base + 7, base + 11, base + 15);
  blamkaG(lo, hi, base + 0, base + 5, base + 10, base + 15);
  blamkaG(lo, hi, base + 1, base + 6, base + 11, base + 12);
  blamkaG(lo, hi, base + 2, base + 7, base + 8, base + 13);
  blamkaG(lo, hi, base + 3, base + 4, base + 9, base + 14);
}

/** BlaMka G 函数：a=a+b+2*aL*bL（mod 2^64），含旋转。 */
function blamkaG(lo: Uint32Array, hi: Uint32Array, a: number, b: number, c: number, d: number): void {
  fBlaMka(lo, hi, a, b);          // a = a + b + 2*lo(a)*lo(b)
  xorRotrIdx(lo, hi, d, a, 32);   // d = rotr64(d ^ a, 32)
  fBlaMka(lo, hi, c, d);          // c = c + d + 2*lo(c)*lo(d)
  xorRotrIdx(lo, hi, b, c, 24);   // b = rotr64(b ^ c, 24)
  fBlaMka(lo, hi, a, b);
  xorRotrIdx(lo, hi, d, a, 16);
  fBlaMka(lo, hi, c, d);
  xorRotrIdx(lo, hi, b, c, 63);
}

/** x[a] = x[a] + x[b] + 2 * lo32(x[a]) * lo32(x[b])（mod 2^64）。 */
function fBlaMka(lo: Uint32Array, hi: Uint32Array, a: number, b: number): void {
  // 计算 2 * (lo(a) * lo(b))，作为 64-bit 加数。
  const aLo: number = lo[a] >>> 0;
  const bLo: number = lo[b] >>> 0;
  // 64-bit 乘积：拆成 16-bit 块避免精度丢失。
  const prod: number[] = mul32to64(aLo, bLo); // [lo32, hi32]
  // 乘 2。
  let mLo: number = (prod[0] << 1) >>> 0;
  let mHi: number = ((prod[1] << 1) | (prod[0] >>> 31)) >>> 0;
  // x[a] = x[a] + x[b]
  add64Idx(lo, hi, a, lo[b], hi[b]);
  // x[a] += m
  add64Idx(lo, hi, a, mLo, mHi);
}

/**
 * 32x32 -> 64 无符号乘，返回 [lo32, hi32]。
 *
 * 关键正确性要点：中间量 `cross = aL*bH + aH*bL` 最大可达 2*(0xffff)^2 ≈ 2^33，
 * **超过 32 位**。因此取其高 16 位必须用浮点除法 `Math.floor(cross/0x10000)`，
 * 绝不能用 `cross >>> 16`（位运算会先把 cross 截断到 32 位，丢失高位 → 进位 bug）。
 * 同理高位累加用浮点除法分离进位，最后再 `>>> 0` 归一化到 32 位。
 */
function mul32to64(a: number, b: number): number[] {
  const aL: number = a & 0xffff;
  const aH: number = a >>> 16;
  const bL: number = b & 0xffff;
  const bH: number = b >>> 16;
  const ll: number = aL * bL;
  const lh: number = aL * bH;
  const hl: number = aH * bL;
  const hh: number = aH * bH;
  // cross 可超过 2^32，用浮点拆分高低 16 位，避免位运算截断。
  const cross: number = lh + hl;
  const crossLo: number = (cross % 0x10000) * 0x10000; // 低 16 位左移 16
  const crossHi: number = Math.floor(cross / 0x10000); // 高位贡献到 hi
  const loFull: number = ll + crossLo;                 // 可达 ~2^33
  const carry: number = Math.floor(loFull / 0x100000000);
  const lo: number = loFull >>> 0;
  const hi: number = (hh + crossHi + carry) >>> 0;
  return [lo, hi];
}

/** 数组下标版 64-bit 加：x[idx] += (addLo,addHi)。 */
function add64Idx(lo: Uint32Array, hi: Uint32Array, idx: number, addLo: number, addHi: number): void {
  const sum: number = (lo[idx] >>> 0) + (addLo >>> 0);
  const carry: number = Math.floor(sum / 0x100000000);
  lo[idx] = sum >>> 0;
  hi[idx] = (hi[idx] + addHi + carry) >>> 0;
}

/** 数组下标版 xor+rotr：x[dst] = rotr64(x[dst] ^ x[src], n)。 */
function xorRotrIdx(lo: Uint32Array, hi: Uint32Array, dst: number, src: number, n: number): void {
  const xl: number = (lo[dst] ^ lo[src]) >>> 0;
  const xh: number = (hi[dst] ^ hi[src]) >>> 0;
  lo[dst] = rotr64Lo(xl, xh, n);
  hi[dst] = rotr64Hi(xl, xh, n);
}

/**
 * 压缩函数 G(X, Y) -> 新块。
 * R = X ^ Y；对 R 做 8 行 + 8 列的 BlaMka 置换得 Z；输出 = Z ^ R。
 * 结果写入 out（out 可与 X/Y 不同实例）。
 */
function argon2G(x: Argon2Block, y: Argon2Block, out: Argon2Block, withXor: boolean, prev: Argon2Block | null): void {
  // R = X ^ Y。
  const rLo: Uint32Array = new Uint32Array(ARGON2_QWORDS);
  const rHi: Uint32Array = new Uint32Array(ARGON2_QWORDS);
  for (let i = 0; i < ARGON2_QWORDS; i++) {
    rLo[i] = (x.lo[i] ^ y.lo[i]) >>> 0;
    rHi[i] = (x.hi[i] ^ y.hi[i]) >>> 0;
  }
  // Z = R 的拷贝，做置换。
  const zLo: Uint32Array = new Uint32Array(ARGON2_QWORDS);
  const zHi: Uint32Array = new Uint32Array(ARGON2_QWORDS);
  zLo.set(rLo);
  zHi.set(rHi);

  // 8 行：每行 16 个连续字（行 i 的 base = i*16）。
  for (let i = 0; i < 8; i++) {
    argon2Permutation(zLo, zHi, i * 16);
  }
  // 8 列：每列由 16 个跨行字组成。需先把列收集到临时 16 字，置换后写回。
  const tLo: Uint32Array = new Uint32Array(16);
  const tHi: Uint32Array = new Uint32Array(16);
  for (let i = 0; i < 8; i++) {
    // 列 i 的 16 个字下标：2*i, 2*i+1, 2*i+16, 2*i+17, ... 每行取 2 个。
    for (let k = 0; k < 8; k++) {
      const idx0: number = k * 16 + 2 * i;
      const idx1: number = k * 16 + 2 * i + 1;
      tLo[k * 2] = zLo[idx0];
      tHi[k * 2] = zHi[idx0];
      tLo[k * 2 + 1] = zLo[idx1];
      tHi[k * 2 + 1] = zHi[idx1];
    }
    argon2Permutation(tLo, tHi, 0);
    for (let k = 0; k < 8; k++) {
      const idx0: number = k * 16 + 2 * i;
      const idx1: number = k * 16 + 2 * i + 1;
      zLo[idx0] = tLo[k * 2];
      zHi[idx0] = tHi[k * 2];
      zLo[idx1] = tLo[k * 2 + 1];
      zHi[idx1] = tHi[k * 2 + 1];
    }
  }
  // out = Z ^ R（若 withXor 则再 ^= prev，即原块）。
  for (let i = 0; i < ARGON2_QWORDS; i++) {
    let lo: number = (zLo[i] ^ rLo[i]) >>> 0;
    let hi: number = (zHi[i] ^ rHi[i]) >>> 0;
    if (withXor && prev !== null) {
      lo = (lo ^ prev.lo[i]) >>> 0;
      hi = (hi ^ prev.hi[i]) >>> 0;
    }
    out.lo[i] = lo;
    out.hi[i] = hi;
  }
}

/** Argon2id 参数与口令/盐输入。 */
export class Argon2Params {
  memoryKib: number;
  timeCost: number;
  parallelism: number;
  outLen: number;
  constructor(memoryKib: number, timeCost: number, parallelism: number, outLen: number) {
    this.memoryKib = memoryKib;
    this.timeCost = timeCost;
    this.parallelism = parallelism;
    this.outLen = outLen;
  }
}

/**
 * Argon2id 主函数。
 * @param password 已 NFC 归一化的口令 UTF-8 字节。
 * @param salt 盐（16 字节）。
 * @param params 内存/时间/并行度/输出长度。
 * @returns 派生密钥（outLen 字节）。
 */
export function argon2id(password: Uint8Array, salt: Uint8Array, params: Argon2Params): Uint8Array {
  const p: number = params.parallelism;
  const tau: number = params.outLen;
  const t: number = params.timeCost;
  const v: number = 0x13;
  const y: number = ARGON2_TYPE_ID;

  // 内存块数：m' = floor(m / (4p)) * 4p。
  const mPrime: number = Math.floor(params.memoryKib / (ARGON2_SYNC_POINTS * p)) * (ARGON2_SYNC_POINTS * p);
  const laneLength: number = Math.floor(mPrime / p); // 每 lane 的块数 q
  const segmentLength: number = Math.floor(laneLength / ARGON2_SYNC_POINTS);

  // ── 计算 H0（64 字节）─────────────────────────────────────────────────
  const parts: Uint8Array[] = [];
  parts.push(le32Bytes(p));
  parts.push(le32Bytes(tau));
  parts.push(le32Bytes(params.memoryKib));
  parts.push(le32Bytes(t));
  parts.push(le32Bytes(v));
  parts.push(le32Bytes(y));
  parts.push(le32Bytes(password.length));
  parts.push(password);
  parts.push(le32Bytes(salt.length));
  parts.push(salt);
  parts.push(le32Bytes(0)); // |K| 密钥长度 0
  parts.push(le32Bytes(0)); // |X| associated data 长度 0
  let total: number = 0;
  for (let i = 0; i < parts.length; i++) {
    total += parts[i].length;
  }
  const h0Input: Uint8Array = new Uint8Array(total);
  let o: number = 0;
  for (let i = 0; i < parts.length; i++) {
    h0Input.set(parts[i], o);
    o += parts[i].length;
  }
  const h0: Uint8Array = blake2b(h0Input, 64); // 64 字节

  // ── 内存矩阵：B[lane][col]，共 p*laneLength 块 ───────────────────────────
  const blocks: Argon2Block[] = [];
  for (let i = 0; i < p * laneLength; i++) {
    blocks.push(new Argon2Block());
  }
  const blockAt = (lane: number, col: number): Argon2Block => blocks[lane * laneLength + col];

  // 初始两列：B[i][0] = H'(H0 ‖ LE32(0) ‖ LE32(i))，B[i][1] = H'(H0 ‖ LE32(1) ‖ LE32(i))。
  for (let lane = 0; lane < p; lane++) {
    for (let col = 0; col < 2; col++) {
      const inp: Uint8Array = new Uint8Array(64 + 8);
      inp.set(h0, 0);
      inp.set(le32Bytes(col), 64);
      inp.set(le32Bytes(lane), 68);
      const blk: Uint8Array = argon2Hprime(inp, ARGON2_BLOCK_SIZE);
      blockAt(lane, col).fromBytes(blk);
    }
  }

  // ── 填充其余块 ───────────────────────────────────────────────────────────
  for (let pass = 0; pass < t; pass++) {
    for (let slice = 0; slice < ARGON2_SYNC_POINTS; slice++) {
      for (let lane = 0; lane < p; lane++) {
        fillSegment(
          blocks, blockAt, pass, slice, lane,
          p, laneLength, segmentLength, t, y,
        );
      }
    }
  }

  // ── 终结：C = B[0][q-1] ^ B[1][q-1] ^ ... ^ B[p-1][q-1]，再 H'(C) 到 tau ──
  const c: Argon2Block = new Argon2Block();
  c.copyFrom(blockAt(0, laneLength - 1));
  for (let lane = 1; lane < p; lane++) {
    c.xorWith(blockAt(lane, laneLength - 1));
  }
  return argon2Hprime(c.toBytes(), tau);
}

/** 填充一个 segment（pass, slice, lane）。 */
function fillSegment(
  blocks: Argon2Block[],
  blockAt: (lane: number, col: number) => Argon2Block,
  pass: number, slice: number, lane: number,
  p: number, laneLength: number, segmentLength: number, t: number, y: number,
): void {
  // Argon2id：第 0 pass 的前两个 slice 用数据无关寻址（Argon2i 风格），其余数据相关。
  const dataIndependent: boolean = (pass === 0 && slice < ARGON2_SYNC_POINTS / 2);

  // 数据无关寻址需要一个 address block（每 128 个地址由 G 重新生成一批 J1/J2）。
  let addressBlock: Argon2Block | null = null;
  let inputBlock: Argon2Block | null = null;
  const zeroBlock: Argon2Block = new Argon2Block();
  if (dataIndependent) {
    inputBlock = new Argon2Block();
    // input = [pass, lane, slice, m', t, y, ctr=0, 0...]
    inputBlock.lo[0] = pass >>> 0; inputBlock.hi[0] = 0;
    inputBlock.lo[1] = lane >>> 0; inputBlock.hi[1] = 0;
    inputBlock.lo[2] = slice >>> 0; inputBlock.hi[2] = 0;
    inputBlock.lo[3] = (p * laneLength) >>> 0; inputBlock.hi[3] = 0;
    inputBlock.lo[4] = t >>> 0; inputBlock.hi[4] = 0;
    inputBlock.lo[5] = y >>> 0; inputBlock.hi[5] = 0;
    addressBlock = new Argon2Block();
  }

  const startingIndex: number = (pass === 0 && slice === 0) ? 2 : 0;

  // 关键正确性要点（对齐官方 phc-winner-argon2 ref.c）：
  //  - address block 用「段内位置 index % 128」直接索引，**不是**单独自增的计数器。
  //  - 当 (pass==0 && slice==0) 时 startingIndex=2，循环内 `index % 128 == 0` 永不在
  //    index=2 触发，故必须在进入循环**之前**先做一次 next_addresses 生成首批地址，
  //    使 index=2 能取到 address_block[2]。漏掉这一步会让 slice 0 用到全零 address block。
  if (dataIndependent && pass === 0 && slice === 0) {
    nextAddresses(inputBlock as Argon2Block, addressBlock as Argon2Block, zeroBlock);
  }

  for (let index = startingIndex; index < segmentLength; index++) {
    const col: number = slice * segmentLength + index;
    if (col >= laneLength) {
      break;
    }
    // 前一块（同 lane，列 col-1；col=0 时回绕到 laneLength-1）。
    const prevCol: number = col === 0 ? laneLength - 1 : col - 1;
    const prevBlock: Argon2Block = blockAt(lane, prevCol);

    // 取 J1/J2（伪随机数对）。
    let j1: number;
    let j2: number;
    if (dataIndependent) {
      if (index % ARGON2_QWORDS === 0) {
        // 每 128 个地址刷新一批：ctr 自增并 G 两次。
        nextAddresses(inputBlock as Argon2Block, addressBlock as Argon2Block, zeroBlock);
      }
      const ab: Argon2Block = addressBlock as Argon2Block;
      const slot: number = index % ARGON2_QWORDS;
      j1 = ab.lo[slot] >>> 0;
      j2 = ab.hi[slot] >>> 0;
    } else {
      // 数据相关：J1/J2 来自前一块的第 0 个 64-bit 字。
      j1 = prevBlock.lo[0] >>> 0;
      j2 = prevBlock.hi[0] >>> 0;
    }

    // 计算引用块 (refLane, refIndex)。
    const refLane: number = (pass === 0 && slice === 0) ? lane : (j2 % p);

    // 候选区大小（reference area size）。
    let referenceAreaSize: number;
    if (pass === 0) {
      if (slice === 0) {
        referenceAreaSize = index - 1; // 同 segment 已生成的块
      } else if (refLane === lane) {
        referenceAreaSize = slice * segmentLength + index - 1;
      } else {
        referenceAreaSize = slice * segmentLength + (index === 0 ? -1 : 0);
      }
    } else {
      if (refLane === lane) {
        referenceAreaSize = laneLength - segmentLength + index - 1;
      } else {
        referenceAreaSize = laneLength - segmentLength + (index === 0 ? -1 : 0);
      }
    }
    if (referenceAreaSize < 0) {
      referenceAreaSize = 0;
    }

    // 相对位置映射（J1 的平方/移位法，RFC 9106 §3.4.1.2）。
    let relativePosition: number = j1 >>> 0;
    relativePosition = (relativePosition * relativePosition) / 0x100000000; // x^2 / 2^32
    relativePosition = Math.floor(relativePosition);
    relativePosition = referenceAreaSize - 1 - Math.floor((referenceAreaSize * relativePosition) / 0x100000000);

    // 起始位置。
    let startPosition: number = 0;
    if (pass !== 0) {
      startPosition = (slice === ARGON2_SYNC_POINTS - 1)
        ? 0
        : (slice + 1) * segmentLength;
    }
    let refIndex: number = (startPosition + relativePosition) % laneLength;
    if (refIndex < 0) {
      refIndex = 0;
    }

    const refBlock: Argon2Block = blockAt(refLane, refIndex);

    // 新块 = G(prevBlock, refBlock)（pass>0 时 ^= 原块）。
    const curBlock: Argon2Block = blockAt(lane, col);
    const withXor: boolean = pass !== 0;
    const original: Argon2Block | null = withXor ? cloneBlock(curBlock) : null;
    argon2G(prevBlock, refBlock, curBlock, withXor, original);
  }
}

/**
 * 生成下一批 address（数据无关寻址用，对齐官方 next_addresses）。
 * 步骤：input.v[6]++；address = G(zero, input)；address = G(zero, address)。
 * 结果写入 addressBlock（原地覆盖）。
 */
function nextAddresses(inputBlock: Argon2Block, addressBlock: Argon2Block, zeroBlock: Argon2Block): void {
  inputBlock.lo[6] = (inputBlock.lo[6] + 1) >>> 0;
  if (inputBlock.lo[6] === 0) {
    // lo 回绕则进位到 hi（64-bit 计数器）。
    inputBlock.hi[6] = (inputBlock.hi[6] + 1) >>> 0;
  }
  argon2G(zeroBlock, inputBlock, addressBlock, false, null);
  argon2G(zeroBlock, addressBlock, addressBlock, false, null);
}

/** 克隆一个块（用于 pass>0 的 with-xor 输出）。 */
function cloneBlock(b: Argon2Block): Argon2Block {
  const c: Argon2Block = new Argon2Block();
  c.copyFrom(b);
  return c;
}

/** 导出 blake2b 供自检/其它模块复用（KDF 内部不直接需要）。 */
export { blake2b };
