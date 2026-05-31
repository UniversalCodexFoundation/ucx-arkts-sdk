/*
 * SPDX-License-Identifier: MIT
 *
 * blake3.ets —— 纯 ArkTS 实现的 BLAKE3 加密哈希（仅默认 hash 模式，32 字节输出）。
 *
 * 背景：HarmonyOS / OpenHarmony 的 @kit.CryptoArchitectureKit 不提供 BLAKE3
 * （仅 SHA1/SHA2 系列/MD5/SM3）。而 BLAKE3 是 UCX MVP 的硬依赖（完整性校验 §5、
 * 双层签名摘要 §6），因此必须自带实现。
 *
 * 本实现忠实移植 BLAKE3 官方 reference_impl 的 Hasher / ChunkState 结构，
 * 已在 SDK 自带的 Node 自检脚本（scripts/verify-blake3.cjs）中对官方测试向量
 * （len = 0,1,63,64,1023,1024,1025,2048,3072,3073,4096,6144）逐一比对通过。
 *
 * 仅实现：unkeyed hash（IV = 标准初始向量），32 字节输出。
 * 不实现 keyed hash / KDF（UCX 不需要）。
 *
 * 参考：BLAKE3 spec（https://github.com/BLAKE3-team/BLAKE3-specs）。
 * ArkTS 注意：用 Uint32Array 做 32-bit 字运算；所有移位用 >>> 保持无符号。
 */

// BLAKE3 初始向量（同 SHA-256 的 IV）。
const IV: Uint32Array = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

// 域分隔标志位。
const CHUNK_START: number = 1 << 0;
const CHUNK_END: number = 1 << 1;
const PARENT: number = 1 << 2;
const ROOT: number = 1 << 3;

const BLOCK_LEN: number = 64;
const CHUNK_LEN: number = 1024;

// 消息字置换表（每轮把 16 个消息字重新排序）。
const MSG_PERMUTATION: number[] = [
  2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8,
];

/**
 * 一个“Output”节点：压缩函数的全部输入（cv ‖ 消息块 ‖ 计数器 ‖ 块长 ‖ flags）。
 * - chainingValue()：取压缩输出前 8 字（非 root 用）。
 * - rootBytes()：加上 ROOT flag 并序列化前 32 字节（root 用）。
 *
 * 用类承载，便于在 finalize 阶段把“尚未决定是否 root”的最末节点延迟到最后再决定。
 */
class Blake3Output {
  inputCv: Uint32Array;
  blockWords: Uint32Array;
  counterLo: number;
  counterHi: number;
  blockLen: number;
  flags: number;

  constructor(
    inputCv: Uint32Array,
    blockWords: Uint32Array,
    counterLo: number,
    counterHi: number,
    blockLen: number,
    flags: number,
  ) {
    this.inputCv = inputCv;
    this.blockWords = blockWords;
    this.counterLo = counterLo;
    this.counterHi = counterHi;
    this.blockLen = blockLen;
    this.flags = flags;
  }

  /** 非 root 节点的 8 字 chaining value。 */
  chainingValue(): Uint32Array {
    const s: Uint32Array = compress(
      this.inputCv, this.blockWords, this.counterLo, this.counterHi, this.blockLen, this.flags,
    );
    return first8(s);
  }

  /** root 节点输出前 32 字节（counter 固定 0；附加 ROOT flag）。 */
  rootBytes(): Uint8Array {
    const s: Uint32Array = compress(
      this.inputCv, this.blockWords, 0, 0, this.blockLen, this.flags | ROOT,
    );
    const out: Uint8Array = new Uint8Array(32);
    for (let i = 0; i < 8; i++) {
      const w: number = s[i] >>> 0;
      out[i * 4] = w & 0xff;
      out[i * 4 + 1] = (w >>> 8) & 0xff;
      out[i * 4 + 2] = (w >>> 16) & 0xff;
      out[i * 4 + 3] = (w >>> 24) & 0xff;
    }
    return out;
  }
}

/** 32-bit 循环右移。 */
function rotr(x: number, n: number): number {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

/** BLAKE3 的 G 混合函数（作用于状态数组 state 的四个下标）。 */
function g(
  state: Uint32Array,
  a: number, b: number, c: number, d: number,
  mx: number, my: number,
): void {
  state[a] = (state[a] + state[b] + mx) >>> 0;
  state[d] = rotr((state[d] ^ state[a]) >>> 0, 16);
  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = rotr((state[b] ^ state[c]) >>> 0, 12);
  state[a] = (state[a] + state[b] + my) >>> 0;
  state[d] = rotr((state[d] ^ state[a]) >>> 0, 8);
  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = rotr((state[b] ^ state[c]) >>> 0, 7);
}

/** 对 16 字状态执行一轮（列混合 + 对角混合）。 */
function roundFn(state: Uint32Array, m: Uint32Array): void {
  // 列。
  g(state, 0, 4, 8, 12, m[0], m[1]);
  g(state, 1, 5, 9, 13, m[2], m[3]);
  g(state, 2, 6, 10, 14, m[4], m[5]);
  g(state, 3, 7, 11, 15, m[6], m[7]);
  // 对角。
  g(state, 0, 5, 10, 15, m[8], m[9]);
  g(state, 1, 6, 11, 12, m[10], m[11]);
  g(state, 2, 7, 8, 13, m[12], m[13]);
  g(state, 3, 4, 9, 14, m[14], m[15]);
}

/** 按消息置换表重排消息字（返回新数组）。 */
function permute(m: Uint32Array): Uint32Array {
  const out: Uint32Array = new Uint32Array(16);
  for (let i = 0; i < 16; i++) {
    out[i] = m[MSG_PERMUTATION[i]];
  }
  return out;
}

/**
 * 压缩函数。返回 16 字的完整状态（含 feed-forward）。
 * 调用方取前 8 字作 chaining value，或全 16 字作 XOF 输出。
 */
function compress(
  cv: Uint32Array,
  blockWords: Uint32Array,
  counterLo: number,
  counterHi: number,
  blockLen: number,
  flags: number,
): Uint32Array {
  const state: Uint32Array = new Uint32Array(16);
  state[0] = cv[0]; state[1] = cv[1]; state[2] = cv[2]; state[3] = cv[3];
  state[4] = cv[4]; state[5] = cv[5]; state[6] = cv[6]; state[7] = cv[7];
  state[8] = IV[0]; state[9] = IV[1]; state[10] = IV[2]; state[11] = IV[3];
  state[12] = counterLo >>> 0;
  state[13] = counterHi >>> 0;
  state[14] = blockLen >>> 0;
  state[15] = flags >>> 0;

  let m: Uint32Array = blockWords;
  for (let r = 0; r < 7; r++) {
    roundFn(state, m);
    if (r < 6) {
      m = permute(m);
    }
  }
  // 输出 feed-forward：前 8 字 ^= 后 8 字；后 8 字 ^= 输入 cv。
  for (let i = 0; i < 8; i++) {
    state[i] = (state[i] ^ state[i + 8]) >>> 0;
    state[i + 8] = (state[i + 8] ^ cv[i]) >>> 0;
  }
  return state;
}

/** 取 16 字状态的前 8 字（拷贝）。 */
function first8(s: Uint32Array): Uint32Array {
  const o: Uint32Array = new Uint32Array(8);
  for (let i = 0; i < 8; i++) {
    o[i] = s[i];
  }
  return o;
}

/** 把 64 字节块（不足按零处理）解析为 16 个小端 u32。 */
function wordsFromBlock(block: Uint8Array, offset: number, len: number): Uint32Array {
  const m: Uint32Array = new Uint32Array(16);
  const limit: number = offset + len;
  for (let i = 0; i < 16; i++) {
    const j: number = offset + i * 4;
    let w: number = 0;
    if (j < limit) {
      const b0: number = block[j];
      const b1: number = j + 1 < limit ? block[j + 1] : 0;
      const b2: number = j + 2 < limit ? block[j + 2] : 0;
      const b3: number = j + 3 < limit ? block[j + 3] : 0;
      w = (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) >>> 0;
    }
    m[i] = w;
  }
  return m;
}

/**
 * 计算一个 chunk（≤1024 字节，含空 chunk）的“最末块 Output”。
 * 前面的块直接压缩成 chaining value；最后一块返回 Blake3Output 以便决定是否 root。
 */
function chunkOutput(
  input: Uint8Array,
  start: number,
  length: number,
  chunkCounter: number,
): Blake3Output {
  let cv: Uint32Array = first8(IV);
  const counterLo: number = chunkCounter >>> 0;
  const counterHi: number = Math.floor(chunkCounter / 0x100000000) >>> 0;

  let blockCount: number = Math.floor((length + BLOCK_LEN - 1) / BLOCK_LEN);
  if (blockCount === 0) {
    blockCount = 1;
  }

  // 处理除最后一块外的所有块。
  for (let b = 0; b < blockCount - 1; b++) {
    const blockStart: number = start + b * BLOCK_LEN;
    const remaining: number = length - b * BLOCK_LEN;
    const thisLen: number = remaining >= BLOCK_LEN ? BLOCK_LEN : remaining;
    const m: Uint32Array = wordsFromBlock(input, blockStart, thisLen);
    let flags: number = 0;
    if (b === 0) {
      flags |= CHUNK_START;
    }
    cv = first8(compress(cv, m, counterLo, counterHi, thisLen, flags));
  }

  // 最后一块。
  const lb: number = blockCount - 1;
  const blockStart: number = start + lb * BLOCK_LEN;
  const remaining: number = length - lb * BLOCK_LEN;
  const thisLen: number = remaining >= BLOCK_LEN ? BLOCK_LEN : (remaining > 0 ? remaining : 0);
  const m: Uint32Array = wordsFromBlock(input, blockStart, thisLen);
  let flags: number = CHUNK_END;
  if (lb === 0) {
    flags |= CHUNK_START;
  }
  return new Blake3Output(cv, m, counterLo, counterHi, thisLen, flags);
}

/** 由左右两个 chaining value 构造父节点 Output（PARENT flag）。 */
function parentOutput(left: Uint32Array, right: Uint32Array): Blake3Output {
  const m: Uint32Array = new Uint32Array(16);
  for (let i = 0; i < 8; i++) {
    m[i] = left[i];
    m[i + 8] = right[i];
  }
  return new Blake3Output(first8(IV), m, 0, 0, BLOCK_LEN, PARENT);
}

/**
 * 计算 BLAKE3，返回 32 字节哈希。
 *
 * 算法（忠实移植 reference_impl）：
 *  1. 逐个 chunk 计算 chaining value，按“subtree 栈合并”规则维护一个 CV 栈：
 *     每入栈一个 chunk，若累计 chunk 数为偶则反复弹栈做父合并（保证最左满子树）。
 *  2. 最后一个 chunk 不入栈，作为初始 output；finalize 阶段从右到左把栈中 CV
 *     逐一与 output 做父合并；最外层父节点用 ROOT flag 输出。
 */
export function blake3(input: Uint8Array): Uint8Array {
  const total: number = input.length;
  const chunkCount: number =
    total === 0 ? 1 : Math.floor((total + CHUNK_LEN - 1) / CHUNK_LEN);

  // CV 栈（每元素 8 字）。
  const cvStack: Uint32Array[] = [];
  let chunksSoFar: number = 0;

  // 处理除最后一个 chunk 外的所有 chunk。
  for (let c = 0; c < chunkCount - 1; c++) {
    const start: number = c * CHUNK_LEN;
    const len: number = Math.min(CHUNK_LEN, total - start);
    let cv: Uint32Array = chunkOutput(input, start, len, c).chainingValue();
    chunksSoFar += 1;
    // 累计 chunk 数为偶则合并（trailing-zero 规则）。
    let t: number = chunksSoFar;
    while ((t & 1) === 0) {
      const left: Uint32Array = cvStack.pop() as Uint32Array;
      cv = parentOutput(left, cv).chainingValue();
      t = t >> 1;
    }
    cvStack.push(cv);
  }

  // 最后一个 chunk -> 初始 output。
  const lastStart: number = (chunkCount - 1) * CHUNK_LEN;
  const lastLen: number = total === 0 ? 0 : Math.min(CHUNK_LEN, total - lastStart);
  let output: Blake3Output = chunkOutput(input, lastStart, lastLen, chunkCount - 1);

  // finalize：从右到左把栈中 CV 与 output 做父合并；最外层用 ROOT 输出。
  while (cvStack.length > 0) {
    const left: Uint32Array = cvStack.pop() as Uint32Array;
    output = parentOutput(left, output.chainingValue());
  }
  return output.rootBytes();
}
