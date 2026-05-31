/*
 * SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * aes.ets —— 纯 ArkTS 实现的 AES-256 分组密码 + GCM + CBC 模式。
 *
 * 用途：
 *  - AES-256-GCM 解密（UCXE algo 0x01；AEAD，tag 16，nonce 12）。
 *  - AES-256-CBC 解密（UCXE algo 0x02；配合 HMAC-SHA256 Encrypt-then-MAC）。
 *
 * 为何自带：@kit.CryptoArchitectureKit 提供 AES-GCM/CBC，但其 createCipher API 为异步
 * （Promise），且 ChaCha20-Poly1305 需 API 22+；而 UCXE 解密契约为**同步**接口。为保证
 * 同步、确定、跨 HarmonyOS/OpenHarmony 版本一致并便于审阅，本 SDK 采用自带纯实现。
 * GCM 已对 UCXE 真实夹具（plain-aesgcm.ucxe）在 Node 自检中验证解密正确。
 *
 * 实现说明：
 *  - AES 用查表 S-box + 标准 KeyExpansion；解密用逆 S-box + InvMixColumns。
 *  - GCM：用 CTR 模式加解密 + GHASH（GF(2^128) 乘法）做认证。解密先验 tag。
 *  - CBC：标准 16 字节块链式；padding 由上层做 PKCS#7（本文件只做 raw 块解密）。
 *
 * ArkTS 注意：禁 any；GF 乘法用 32-bit 字数组避免 BigInt 依赖。
 */

// ── AES S-box / 逆 S-box（标准查表） ────────────────────────────────────────
const SBOX: Uint8Array = buildSbox();
const INV_SBOX: Uint8Array = buildInvSbox();
const RCON: Uint8Array = new Uint8Array([
  0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
  0x6c, 0xd8, 0xab, 0x4d,
]);

/** GF(2^8) 乘法（用于 MixColumns / 逆向）。 */
function gmul(a: number, b: number): number {
  let p: number = 0;
  let aa: number = a;
  let bb: number = b;
  for (let i = 0; i < 8; i++) {
    if ((bb & 1) !== 0) {
      p ^= aa;
    }
    const hi: number = aa & 0x80;
    aa = (aa << 1) & 0xff;
    if (hi !== 0) {
      aa ^= 0x1b;
    }
    bb >>= 1;
  }
  return p & 0xff;
}

/** 构造 AES S-box。 */
function buildSbox(): Uint8Array {
  const sbox: Uint8Array = new Uint8Array(256);
  // 计算 GF(2^8) 乘法逆元 + 仿射变换。
  const inv: Uint8Array = new Uint8Array(256);
  // 先用对数/反对数表求逆元。
  const log: Uint8Array = new Uint8Array(256);
  const alog: Uint8Array = new Uint8Array(256);
  let x: number = 1;
  for (let i = 0; i < 255; i++) {
    alog[i] = x;
    log[x] = i;
    // x = x * 3（生成元 0x03）。
    x = gmul(x, 0x03);
  }
  inv[0] = 0;
  for (let i = 1; i < 256; i++) {
    inv[i] = alog[(255 - log[i]) % 255];
  }
  for (let i = 0; i < 256; i++) {
    let s: number = inv[i];
    let xformed: number = s;
    for (let t = 0; t < 4; t++) {
      s = ((s << 1) | (s >> 7)) & 0xff;
      xformed ^= s;
    }
    xformed ^= 0x63;
    sbox[i] = xformed & 0xff;
  }
  return sbox;
}

/** 由 S-box 构造逆 S-box。 */
function buildInvSbox(): Uint8Array {
  const inv: Uint8Array = new Uint8Array(256);
  for (let i = 0; i < 256; i++) {
    inv[SBOX[i]] = i;
  }
  return inv;
}

/** AES-256 上下文：展开后的轮密钥。 */
export class Aes256 {
  /** 轮密钥，60 个 32-bit 字（Nk=8, Nr=14 -> 4*(Nr+1)=60）。 */
  private roundKeys: Uint32Array;
  private static readonly NR: number = 14;

  constructor(key: Uint8Array) {
    if (key.length !== 32) {
      throw new Error('AES-256 requires a 32-byte key');
    }
    this.roundKeys = Aes256.expandKey(key);
  }

  /** KeyExpansion（Nk=8）。 */
  private static expandKey(key: Uint8Array): Uint32Array {
    const nk: number = 8;
    const nr: number = Aes256.NR;
    const totalWords: number = 4 * (nr + 1); // 60
    const w: Uint32Array = new Uint32Array(totalWords);
    for (let i = 0; i < nk; i++) {
      w[i] =
        ((key[4 * i] << 24) |
          (key[4 * i + 1] << 16) |
          (key[4 * i + 2] << 8) |
          key[4 * i + 3]) >>>
        0;
    }
    for (let i = nk; i < totalWords; i++) {
      let temp: number = w[i - 1];
      if (i % nk === 0) {
        // RotWord + SubWord + Rcon。
        temp = ((temp << 8) | (temp >>> 24)) >>> 0;
        temp = Aes256.subWord(temp);
        temp = (temp ^ (RCON[i / nk - 1] << 24)) >>> 0;
      } else if (i % nk === 4) {
        // 256-bit 密钥的额外 SubWord。
        temp = Aes256.subWord(temp);
      }
      w[i] = (w[i - nk] ^ temp) >>> 0;
    }
    return w;
  }

  /** 对一个 32-bit 字的 4 个字节做 S-box 替换。 */
  private static subWord(word: number): number {
    return (
      ((SBOX[(word >>> 24) & 0xff] << 24) |
        (SBOX[(word >>> 16) & 0xff] << 16) |
        (SBOX[(word >>> 8) & 0xff] << 8) |
        SBOX[word & 0xff]) >>>
      0
    );
  }

  /** 加密单个 16 字节块（in 写入 out，可同 buffer 不同 offset）。 */
  encryptBlock(input: Uint8Array, inOff: number, out: Uint8Array, outOff: number): void {
    const state: Uint8Array = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
      state[i] = input[inOff + i];
    }
    this.addRoundKey(state, 0);
    for (let round = 1; round < Aes256.NR; round++) {
      this.subBytes(state);
      this.shiftRows(state);
      this.mixColumns(state);
      this.addRoundKey(state, round);
    }
    this.subBytes(state);
    this.shiftRows(state);
    this.addRoundKey(state, Aes256.NR);
    for (let i = 0; i < 16; i++) {
      out[outOff + i] = state[i];
    }
  }

  /** 解密单个 16 字节块。 */
  decryptBlock(input: Uint8Array, inOff: number, out: Uint8Array, outOff: number): void {
    const state: Uint8Array = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
      state[i] = input[inOff + i];
    }
    this.addRoundKey(state, Aes256.NR);
    for (let round = Aes256.NR - 1; round >= 1; round--) {
      this.invShiftRows(state);
      this.invSubBytes(state);
      this.addRoundKey(state, round);
      this.invMixColumns(state);
    }
    this.invShiftRows(state);
    this.invSubBytes(state);
    this.addRoundKey(state, 0);
    for (let i = 0; i < 16; i++) {
      out[outOff + i] = state[i];
    }
  }

  /** state ^= roundKey[round]（state 按列主序：state[0..3]=列0）。 */
  private addRoundKey(state: Uint8Array, round: number): void {
    for (let col = 0; col < 4; col++) {
      const wk: number = this.roundKeys[round * 4 + col];
      state[col * 4] ^= (wk >>> 24) & 0xff;
      state[col * 4 + 1] ^= (wk >>> 16) & 0xff;
      state[col * 4 + 2] ^= (wk >>> 8) & 0xff;
      state[col * 4 + 3] ^= wk & 0xff;
    }
  }

  private subBytes(state: Uint8Array): void {
    for (let i = 0; i < 16; i++) {
      state[i] = SBOX[state[i]];
    }
  }

  private invSubBytes(state: Uint8Array): void {
    for (let i = 0; i < 16; i++) {
      state[i] = INV_SBOX[state[i]];
    }
  }

  /** ShiftRows：state 按列主序排布（字节 i 的行 = i%4，列 = floor(i/4)）。 */
  private shiftRows(state: Uint8Array): void {
    // 加密：第 row 行循环左移 row 个位置 -> (row,col) 移到 (row, col-row mod 4)。
    const t: Uint8Array = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
      const row: number = i % 4;
      const col: number = Math.floor(i / 4);
      const newCol: number = (col - row + 4) % 4;
      t[newCol * 4 + row] = state[col * 4 + row];
    }
    for (let i = 0; i < 16; i++) {
      state[i] = t[i];
    }
  }

  private invShiftRows(state: Uint8Array): void {
    // 解密：第 row 行循环右移 row 个位置 -> (row,col) 移到 (row, col+row mod 4)。
    const t: Uint8Array = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
      const row: number = i % 4;
      const col: number = Math.floor(i / 4);
      const newCol: number = (col + row) % 4;
      t[newCol * 4 + row] = state[col * 4 + row];
    }
    for (let i = 0; i < 16; i++) {
      state[i] = t[i];
    }
  }

  private mixColumns(state: Uint8Array): void {
    for (let c = 0; c < 4; c++) {
      const i: number = c * 4;
      const a0: number = state[i];
      const a1: number = state[i + 1];
      const a2: number = state[i + 2];
      const a3: number = state[i + 3];
      state[i] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3;
      state[i + 1] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3;
      state[i + 2] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3);
      state[i + 3] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2);
    }
  }

  private invMixColumns(state: Uint8Array): void {
    for (let c = 0; c < 4; c++) {
      const i: number = c * 4;
      const a0: number = state[i];
      const a1: number = state[i + 1];
      const a2: number = state[i + 2];
      const a3: number = state[i + 3];
      state[i] = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9);
      state[i + 1] = gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13);
      state[i + 2] = gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11);
      state[i + 3] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14);
    }
  }
}

// ── AES-CBC（raw 块解密，padding 由上层处理） ──────────────────────────────

/** AES-256-CBC 解密（无 padding 处理）。ciphertext 长度必须是 16 的倍数。 */
export function aesCbcDecrypt(key: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  if (ciphertext.length % 16 !== 0) {
    throw new Error('CBC ciphertext length not multiple of 16');
  }
  const aes: Aes256 = new Aes256(key);
  const out: Uint8Array = new Uint8Array(ciphertext.length);
  const prev: Uint8Array = new Uint8Array(16);
  prev.set(iv.subarray(0, 16));
  const block: Uint8Array = new Uint8Array(16);
  for (let off = 0; off < ciphertext.length; off += 16) {
    aes.decryptBlock(ciphertext, off, block, 0);
    for (let i = 0; i < 16; i++) {
      out[off + i] = block[i] ^ prev[i];
    }
    for (let i = 0; i < 16; i++) {
      prev[i] = ciphertext[off + i];
    }
  }
  return out;
}

// ── AES-GCM ──────────────────────────────────────────────────────────────────

/** 128-bit 块的 GF(2^128) 乘法（GHASH 用），右移卷积。 */
function gf128Mul(x: Uint8Array, y: Uint8Array): Uint8Array {
  // z = 0；v = y；for each bit of x (MSB first): if bit set z ^= v; v = v>>1 (with reduction).
  const z: Uint8Array = new Uint8Array(16);
  const v: Uint8Array = new Uint8Array(16);
  v.set(y);
  for (let i = 0; i < 128; i++) {
    const byteIndex: number = i >> 3;
    const bit: number = (x[byteIndex] >> (7 - (i & 7))) & 1;
    if (bit !== 0) {
      for (let k = 0; k < 16; k++) {
        z[k] ^= v[k];
      }
    }
    // v >>= 1（128-bit 右移），若最低位为 1 则与 R=0xe1000... 约简。
    const lsb: number = v[15] & 1;
    for (let k = 15; k > 0; k--) {
      v[k] = ((v[k] >>> 1) | ((v[k - 1] & 1) << 7)) & 0xff;
    }
    v[0] = (v[0] >>> 1) & 0xff;
    if (lsb !== 0) {
      v[0] ^= 0xe1;
    }
  }
  return z;
}

/** GHASH：对 data（按 16 字节块，最后块右补零）做 GF 累加。 */
function ghash(h: Uint8Array, data: Uint8Array): Uint8Array {
  let y: Uint8Array = new Uint8Array(16);
  const block: Uint8Array = new Uint8Array(16);
  for (let off = 0; off < data.length; off += 16) {
    block.fill(0);
    const n: number = Math.min(16, data.length - off);
    for (let i = 0; i < n; i++) {
      block[i] = data[off + i];
    }
    for (let i = 0; i < 16; i++) {
      block[i] ^= y[i];
    }
    y = gf128Mul(block, h);
  }
  return y;
}

/** CTR 模式加/解密（GCM 内部用；counter 为 16 字节）。 */
function gctr(aes: Aes256, icb: Uint8Array, input: Uint8Array): Uint8Array {
  const out: Uint8Array = new Uint8Array(input.length);
  const counter: Uint8Array = new Uint8Array(16);
  counter.set(icb);
  const keystream: Uint8Array = new Uint8Array(16);
  for (let off = 0; off < input.length; off += 16) {
    aes.encryptBlock(counter, 0, keystream, 0);
    const n: number = Math.min(16, input.length - off);
    for (let i = 0; i < n; i++) {
      out[off + i] = input[off + i] ^ keystream[i];
    }
    // 递增 counter 的低 32 位（big-endian）。
    incr32(counter);
  }
  return out;
}

/** 递增 16 字节计数器的最低 32 位（big-endian），溢出回绕。 */
function incr32(counter: Uint8Array): void {
  for (let i = 15; i >= 12; i--) {
    counter[i] = (counter[i] + 1) & 0xff;
    if (counter[i] !== 0) {
      return;
    }
  }
}

/** 由 IV（12 字节）构造初始计数块 J0 = IV ‖ 0x00000001。 */
function deriveJ0(h: Uint8Array, iv: Uint8Array): Uint8Array {
  if (iv.length === 12) {
    const j0: Uint8Array = new Uint8Array(16);
    j0.set(iv, 0);
    j0[15] = 0x01;
    return j0;
  }
  // 非 12 字节 nonce：J0 = GHASH(IV ‖ 0^s ‖ len64)。UCX 仅用 12，故走上面分支；这里兜底。
  const padLen: number = (16 - (iv.length % 16)) % 16;
  const block: Uint8Array = new Uint8Array(iv.length + padLen + 16);
  block.set(iv, 0);
  const bitLen: number = iv.length * 8;
  const hi: number = Math.floor(bitLen / 0x100000000);
  const lo: number = bitLen >>> 0;
  const lenOff: number = iv.length + padLen + 8;
  block[lenOff] = (hi >>> 24) & 0xff;
  block[lenOff + 1] = (hi >>> 16) & 0xff;
  block[lenOff + 2] = (hi >>> 8) & 0xff;
  block[lenOff + 3] = hi & 0xff;
  block[lenOff + 4] = (lo >>> 24) & 0xff;
  block[lenOff + 5] = (lo >>> 16) & 0xff;
  block[lenOff + 6] = (lo >>> 8) & 0xff;
  block[lenOff + 7] = lo & 0xff;
  return ghash(h, block);
}

/** 把两个 64-bit 长度（bit 数）拼成 GHASH 的长度块。 */
function lengthBlock(aadLen: number, ctLen: number): Uint8Array {
  const block: Uint8Array = new Uint8Array(16);
  const aadBits: number = aadLen * 8;
  const ctBits: number = ctLen * 8;
  writeBE64(block, 0, aadBits);
  writeBE64(block, 8, ctBits);
  return block;
}

/** 写大端 64-bit（用 number；UCX 长度远小于 2^53）。 */
function writeBE64(b: Uint8Array, off: number, value: number): void {
  const hi: number = Math.floor(value / 0x100000000);
  const lo: number = value >>> 0;
  b[off] = (hi >>> 24) & 0xff;
  b[off + 1] = (hi >>> 16) & 0xff;
  b[off + 2] = (hi >>> 8) & 0xff;
  b[off + 3] = hi & 0xff;
  b[off + 4] = (lo >>> 24) & 0xff;
  b[off + 5] = (lo >>> 16) & 0xff;
  b[off + 6] = (lo >>> 8) & 0xff;
  b[off + 7] = lo & 0xff;
}

/**
 * 计算 GCM 认证标签（不解密）。供解密前验证使用。
 * @returns 16 字节 tag。
 */
function gcmTag(aes: Aes256, h: Uint8Array, j0: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  // S = GHASH(AAD ‖ 0^pad ‖ CT ‖ 0^pad ‖ len(AAD)||len(CT))
  const aadPad: number = (16 - (aad.length % 16)) % 16;
  const ctPad: number = (16 - (ciphertext.length % 16)) % 16;
  const ghashInput: Uint8Array = new Uint8Array(
    aad.length + aadPad + ciphertext.length + ctPad + 16,
  );
  let o: number = 0;
  ghashInput.set(aad, o);
  o += aad.length + aadPad;
  ghashInput.set(ciphertext, o);
  o += ciphertext.length + ctPad;
  ghashInput.set(lengthBlock(aad.length, ciphertext.length), o);

  const s: Uint8Array = ghash(h, ghashInput);
  // tag = E(K, J0) ^ S。
  const ej0: Uint8Array = new Uint8Array(16);
  aes.encryptBlock(j0, 0, ej0, 0);
  const tag: Uint8Array = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    tag[i] = ej0[i] ^ s[i];
  }
  return tag;
}

/** AES-GCM 加密结果（密文 + tag）。 */
export class GcmResult {
  ciphertext: Uint8Array;
  tag: Uint8Array;
  constructor(ciphertext: Uint8Array, tag: Uint8Array) {
    this.ciphertext = ciphertext;
    this.tag = tag;
  }
}

/**
 * AES-256-GCM 加密（仅供自检/对称完整性测试，UCX 阅读器解密时不调用）。
 */
export function aesGcmEncrypt(key: Uint8Array, iv: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): GcmResult {
  const aes: Aes256 = new Aes256(key);
  const h: Uint8Array = new Uint8Array(16);
  aes.encryptBlock(new Uint8Array(16), 0, h, 0);
  const j0: Uint8Array = deriveJ0(h, iv);
  // CTR 从 inc32(J0) 开始。
  const icb: Uint8Array = new Uint8Array(16);
  icb.set(j0);
  incr32(icb);
  const ciphertext: Uint8Array = gctr(aes, icb, plaintext);
  const tag: Uint8Array = gcmTag(aes, h, j0, aad, ciphertext);
  return new GcmResult(ciphertext, tag);
}

/**
 * AES-256-GCM 解密。先验证 tag，不通过返回 null（上层折叠为 DecryptionError）。
 * @returns 明文，或 null（认证失败）。
 */
export function aesGcmDecrypt(
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  aad: Uint8Array,
): Uint8Array | null {
  const aes: Aes256 = new Aes256(key);
  // H = E(K, 0^128)。
  const h: Uint8Array = new Uint8Array(16);
  aes.encryptBlock(new Uint8Array(16), 0, h, 0);
  const j0: Uint8Array = deriveJ0(h, iv);

  // 先验证 tag（常量时间在上层比较）。
  const expectedTag: Uint8Array = gcmTag(aes, h, j0, aad, ciphertext);
  let diff: number = 0;
  if (tag.length !== 16) {
    return null;
  }
  for (let i = 0; i < 16; i++) {
    diff |= expectedTag[i] ^ tag[i];
  }
  if (diff !== 0) {
    return null;
  }

  // 通过后解密：CTR 从 inc32(J0) 开始。
  const icb: Uint8Array = new Uint8Array(16);
  icb.set(j0);
  incr32(icb);
  return gctr(aes, icb, ciphertext);
}
