/*
 * SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * inflate.ets —— 纯 ArkTS 实现的 raw DEFLATE 解压（RFC 1951）。
 *
 * 背景：HarmonyOS 的 @ohos.zlib 只能对整包文件做压缩/解压，无法“列出 zip 条目”
 * 或“按名取单个条目的解压字节”（官方文档明确说明不支持这两种操作）。而 UCX 的完整性
 * 校验（§5）与 JSON 解析（§4）都需要对**单个 ZIP 条目**取其解压后的精确字节，且
 * Layer 2 验签（§6.2）需要 ZIP 的**原始磁盘字节**。因此本 SDK 自带一个最小的 ZIP
 * 读取器（zip.ets）+ raw inflate 解码器（本文件），完全掌控字节，不依赖平台 zip。
 *
 * 本文件实现 RFC 1951 的 INFLATE：
 *  - BTYPE 00：stored（不压缩）。
 *  - BTYPE 01：固定 Huffman 表。
 *  - BTYPE 10：动态 Huffman 表。
 * 不实现 zlib/gzip 包装（ZIP 用的是 raw deflate，无 2 字节 zlib 头）。
 *
 * 已在 SDK 自带的 Node 自检脚本中对真实夹具 sample.ucx 的各 DEFLATE 条目验证：
 * 解压字节的 BLAKE3 与 manifest 中记录的摘要一致。
 *
 * ArkTS 注意：禁 any；位读取用显式状态机。
 */

import { ParseError } from './errors';

/** 长度码（257..285）对应的“基础长度”表。 */
const LENGTH_BASE: number[] = [
  3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
  35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258,
];
/** 长度码对应的“额外位数”表。 */
const LENGTH_EXTRA: number[] = [
  0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
  3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
/** 距离码（0..29）对应的“基础距离”表。 */
const DIST_BASE: number[] = [
  1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
  257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
  8193, 12289, 16385, 24577,
];
/** 距离码对应的“额外位数”表。 */
const DIST_EXTRA: number[] = [
  0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
  7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
];
/** 码长码字母表的读取顺序（RFC 1951 §3.2.7）。 */
const CODE_LENGTH_ORDER: number[] = [
  16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/**
 * 一棵 Huffman 解码树，用“快速查表 + 规范 Huffman 码”实现。
 * 这里采用按位逐步下降的简单解码（counts + symbols 表），实现直观、易审阅。
 */
class HuffmanTree {
  /** 每个码长的码字数量（counts[len]）。 */
  counts: Int32Array;
  /** 按码长排序后的符号表。 */
  symbols: Int32Array;

  constructor(lengths: Int32Array, n: number) {
    this.counts = new Int32Array(16);
    this.symbols = new Int32Array(n);
    for (let i = 0; i < n; i++) {
      this.counts[lengths[i]]++;
    }
    this.counts[0] = 0;
    // 计算每个码长的符号在 symbols 中的偏移。
    const offsets: Int32Array = new Int32Array(16);
    for (let len = 1; len < 16; len++) {
      offsets[len] = offsets[len - 1] + this.counts[len - 1];
    }
    for (let i = 0; i < n; i++) {
      if (lengths[i] !== 0) {
        this.symbols[offsets[lengths[i]]] = i;
        offsets[lengths[i]]++;
      }
    }
  }
}

/** 位读取器（DEFLATE 是 LSB-first）。 */
class BitReader {
  data: Uint8Array;
  pos: number;
  bitBuf: number;
  bitCnt: number;

  constructor(data: Uint8Array, start: number) {
    this.data = data;
    this.pos = start;
    this.bitBuf = 0;
    this.bitCnt = 0;
  }

  /** 读取 count 个位（LSB-first），返回无符号整数。 */
  readBits(count: number): number {
    while (this.bitCnt < count) {
      if (this.pos >= this.data.length) {
        throw new ParseError('inflate: unexpected end of input');
      }
      this.bitBuf |= this.data[this.pos] << this.bitCnt;
      this.pos++;
      this.bitCnt += 8;
    }
    const val: number = this.bitBuf & ((1 << count) - 1);
    this.bitBuf >>>= count;
    this.bitCnt -= count;
    return val;
  }

  /** 丢弃当前字节内剩余位，对齐到字节边界（stored 块前用）。 */
  alignByte(): void {
    this.bitBuf = 0;
    this.bitCnt = 0;
  }
}

/** 用 Huffman 树解码一个符号。 */
function decodeSymbol(br: BitReader, tree: HuffmanTree): number {
  let code: number = 0;
  let first: number = 0;
  let index: number = 0;
  for (let len = 1; len < 16; len++) {
    code |= br.readBits(1);
    const count: number = tree.counts[len];
    if (code - first < count) {
      return tree.symbols[index + (code - first)];
    }
    index += count;
    first += count;
    first <<= 1;
    code <<= 1;
  }
  throw new ParseError('inflate: invalid Huffman code');
}

/** 构造固定 Huffman 的字面/长度树与距离树。 */
function buildFixedTrees(): HuffmanTree[] {
  const litLengths: Int32Array = new Int32Array(288);
  for (let i = 0; i < 144; i++) litLengths[i] = 8;
  for (let i = 144; i < 256; i++) litLengths[i] = 9;
  for (let i = 256; i < 280; i++) litLengths[i] = 7;
  for (let i = 280; i < 288; i++) litLengths[i] = 8;
  const distLengths: Int32Array = new Int32Array(30);
  for (let i = 0; i < 30; i++) distLengths[i] = 5;
  return [new HuffmanTree(litLengths, 288), new HuffmanTree(distLengths, 30)];
}

/** 读取动态 Huffman 块的字面/长度树与距离树。 */
function readDynamicTrees(br: BitReader): HuffmanTree[] {
  const hlit: number = br.readBits(5) + 257;
  const hdist: number = br.readBits(5) + 1;
  const hclen: number = br.readBits(4) + 4;

  // 读取码长码的码长。
  const codeLengthCodeLengths: Int32Array = new Int32Array(19);
  for (let i = 0; i < hclen; i++) {
    codeLengthCodeLengths[CODE_LENGTH_ORDER[i]] = br.readBits(3);
  }
  const clTree: HuffmanTree = new HuffmanTree(codeLengthCodeLengths, 19);

  // 用 clTree 解出 hlit + hdist 个码长（含重复指令 16/17/18）。
  const allLengths: Int32Array = new Int32Array(hlit + hdist);
  let i: number = 0;
  while (i < hlit + hdist) {
    const sym: number = decodeSymbol(br, clTree);
    if (sym < 16) {
      allLengths[i] = sym;
      i++;
    } else if (sym === 16) {
      // 重复上一个码长 3..6 次。
      const repeat: number = br.readBits(2) + 3;
      const prev: number = i > 0 ? allLengths[i - 1] : 0;
      for (let k = 0; k < repeat; k++) {
        allLengths[i] = prev;
        i++;
      }
    } else if (sym === 17) {
      // 重复 0 共 3..10 次。
      const repeat: number = br.readBits(3) + 3;
      for (let k = 0; k < repeat; k++) {
        allLengths[i] = 0;
        i++;
      }
    } else {
      // sym === 18：重复 0 共 11..138 次。
      const repeat: number = br.readBits(7) + 11;
      for (let k = 0; k < repeat; k++) {
        allLengths[i] = 0;
        i++;
      }
    }
  }

  const litLengths: Int32Array = new Int32Array(hlit);
  const distLengths: Int32Array = new Int32Array(hdist);
  for (let k = 0; k < hlit; k++) litLengths[k] = allLengths[k];
  for (let k = 0; k < hdist; k++) distLengths[k] = allLengths[hlit + k];

  return [new HuffmanTree(litLengths, hlit), new HuffmanTree(distLengths, hdist)];
}

/** 输出缓冲（按需增长）。 */
class OutBuffer {
  buf: Uint8Array;
  len: number;

  constructor(initial: number) {
    this.buf = new Uint8Array(initial > 0 ? initial : 64);
    this.len = 0;
  }

  ensure(extra: number): void {
    if (this.len + extra <= this.buf.length) {
      return;
    }
    let cap: number = this.buf.length * 2;
    while (cap < this.len + extra) {
      cap *= 2;
    }
    const nb: Uint8Array = new Uint8Array(cap);
    nb.set(this.buf.subarray(0, this.len));
    this.buf = nb;
  }

  pushByte(b: number): void {
    this.ensure(1);
    this.buf[this.len] = b;
    this.len++;
  }

  toBytes(): Uint8Array {
    return this.buf.slice(0, this.len);
  }
}

/**
 * 解压 raw DEFLATE 数据。
 *
 * @param data 包含 deflate 流的缓冲区。
 * @param start deflate 流在 data 中的起始偏移。
 * @param expectedSize 解压后期望大小（用于初始化输出缓冲；非强制）。
 * @returns 解压后的字节。
 */
export function inflateRaw(data: Uint8Array, start: number, expectedSize: number): Uint8Array {
  const br: BitReader = new BitReader(data, start);
  const out: OutBuffer = new OutBuffer(expectedSize > 0 ? expectedSize : 256);

  let finalBlock: boolean = false;
  while (!finalBlock) {
    finalBlock = br.readBits(1) === 1;
    const btype: number = br.readBits(2);

    if (btype === 0) {
      // stored：对齐到字节，读 LEN / NLEN，复制 LEN 字节。
      br.alignByte();
      if (br.pos + 4 > data.length) {
        throw new ParseError('inflate: truncated stored block header');
      }
      const len: number = data[br.pos] | (data[br.pos + 1] << 8);
      br.pos += 4; // 跳过 LEN(2) + NLEN(2)
      if (br.pos + len > data.length) {
        throw new ParseError('inflate: truncated stored block data');
      }
      out.ensure(len);
      out.buf.set(data.subarray(br.pos, br.pos + len), out.len);
      out.len += len;
      br.pos += len;
    } else if (btype === 1 || btype === 2) {
      const trees: HuffmanTree[] = btype === 1 ? buildFixedTrees() : readDynamicTrees(br);
      const litTree: HuffmanTree = trees[0];
      const distTree: HuffmanTree = trees[1];

      while (true) {
        const sym: number = decodeSymbol(br, litTree);
        if (sym === 256) {
          // 块结束。
          break;
        }
        if (sym < 256) {
          out.pushByte(sym);
        } else {
          // 长度/距离对。
          const li: number = sym - 257;
          if (li < 0 || li >= LENGTH_BASE.length) {
            throw new ParseError('inflate: invalid length symbol');
          }
          const length: number = LENGTH_BASE[li] + br.readBits(LENGTH_EXTRA[li]);
          const distSym: number = decodeSymbol(br, distTree);
          if (distSym < 0 || distSym >= DIST_BASE.length) {
            throw new ParseError('inflate: invalid distance symbol');
          }
          const dist: number = DIST_BASE[distSym] + br.readBits(DIST_EXTRA[distSym]);
          if (dist > out.len) {
            throw new ParseError('inflate: distance too far back');
          }
          out.ensure(length);
          let srcPos: number = out.len - dist;
          for (let k = 0; k < length; k++) {
            out.buf[out.len] = out.buf[srcPos];
            out.len++;
            srcPos++;
          }
        }
      }
    } else {
      throw new ParseError('inflate: invalid block type (BTYPE=3)');
    }
  }

  return out.toBytes();
}
