/*
 * SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * zip.ets —— 最小 ZIP 容器读取（自带，不依赖 @ohos.zlib）。
 *
 * 设计说明：
 * - @ohos.zlib 无法“列出条目”或“按名取单条目解压字节”，因此本 SDK 自带 ZIP 读取器，
 *   完全掌控字节，满足三项需求：
 *     (a) 取每个条目的“解压后字节”（integrity §5 / 解析 §4 需要）。
 *     (b) 保留“原始磁盘字节”（Layer 2 §6.2 需要 EOCD / CD 偏移 / 签名块定位）。
 *     (c) 校验 mimetype 是第一个条目（§2.1）。
 * - 通过中央目录（Central Directory）遍历条目，按 CD 顺序（= builder 写入顺序）返回
 *   条目名列表；从 local file header 取压缩数据并解压（STORED 直拷，DEFLATE 走 inflate）。
 *
 * 注意：压缩方式不影响完整性（§2.3：哈希均作用于解压字节）。mimetype 的 STORED 要求由
 * §2.1 的“位置 + 内容”检查覆盖（参考实现也只校验 index 0 的名字与内容）。
 *
 * ArkTS 注意：禁 any；用显式类型与 Map<string, Uint8Array>。
 */

import { InvalidFormatError } from './errors';
import { ZIP_MAGIC } from './constants';
import { inflateRaw } from './inflate';
import { readU16LE, readU32LE, utf8Decode } from './util';

/** 解析后的 ZIP 视图：解压条目 + 原始字节。 */
export class ZipView {
  /** 条目名 -> 解压后字节。 */
  entries: Map<string, Uint8Array>;
  /** 条目名的有序列表（= CD / 写入顺序）。 */
  order: string[];
  /** 原始磁盘字节（Layer 2 需要）。 */
  raw: Uint8Array;

  constructor(entries: Map<string, Uint8Array>, order: string[], raw: Uint8Array) {
    this.entries = entries;
    this.order = order;
    this.raw = raw;
  }

  /** 取条目解压字节；不存在返回 undefined。 */
  get(name: string): Uint8Array | undefined {
    return this.entries.get(name);
  }
}

/** ZIP EOCD 定位结果。 */
export class EocdInfo {
  /** EOCD 记录起始偏移（指向 50 4B 05 06）。 */
  eocdOffset: number;
  /** 中央目录起始偏移（EOCD+16 的 u32 LE）。 */
  cdOffset: number;
  /** 中央目录条目数（EOCD+10 的 u16 LE）。 */
  cdCount: number;

  constructor(eocdOffset: number, cdOffset: number, cdCount: number) {
    this.eocdOffset = eocdOffset;
    this.cdOffset = cdOffset;
    this.cdCount = cdCount;
  }
}

/**
 * 反向扫描定位 EOCD（End Of Central Directory）记录。
 * 参考 UCX-FORMAT §6.2.1：找 50 4B 05 06，并校验 comment-length 字段与文件尾一致。
 * @returns EOCD 信息；找不到合法 EOCD 时返回 null。
 */
export function findEocd(data: Uint8Array): EocdInfo | null {
  const minEocd: number = 22;
  if (data.length < minEocd) {
    return null;
  }
  const maxBack: number = Math.min(data.length, minEocd + 0xffff);
  const start: number = data.length - minEocd;
  const lowerBound: number = data.length - maxBack;
  for (let i = start; i >= lowerBound; i--) {
    if (
      data[i] === 0x50 &&
      data[i + 1] === 0x4b &&
      data[i + 2] === 0x05 &&
      data[i + 3] === 0x06
    ) {
      const commentLen: number = readU16LE(data, i + 20);
      if (i + minEocd + commentLen === data.length) {
        const cdCount: number = readU16LE(data, i + 10);
        const cdOffset: number = readU32LE(data, i + 16);
        return new EocdInfo(i, cdOffset, cdCount);
      }
    }
  }
  return null;
}

/** 从 local file header 起始处取压缩数据并解压一个条目。 */
function extractEntry(
  data: Uint8Array,
  localHeaderOffset: number,
  compressionFromCd: number,
  compressedSizeFromCd: number,
  uncompressedSizeFromCd: number,
): Uint8Array {
  // Local file header：
  //  0: signature PK\x03\x04 (4)
  //  4: version needed (2)
  //  6: flags (2)
  //  8: compression method (2)
  //  10: mod time (2) / 12: mod date (2)
  //  14: crc32 (4) / 18: compressed size (4) / 22: uncompressed size (4)
  //  26: file name length (2) / 28: extra field length (2)
  //  30: file name / extra / data
  if (
    data[localHeaderOffset] !== 0x50 ||
    data[localHeaderOffset + 1] !== 0x4b ||
    data[localHeaderOffset + 2] !== 0x03 ||
    data[localHeaderOffset + 3] !== 0x04
  ) {
    throw new InvalidFormatError('ZIP: bad local file header signature');
  }
  const compression: number = readU16LE(data, localHeaderOffset + 8);
  const nameLen: number = readU16LE(data, localHeaderOffset + 26);
  const extraLen: number = readU16LE(data, localHeaderOffset + 28);
  const dataStart: number = localHeaderOffset + 30 + nameLen + extraLen;

  // 优先用 CD 的大小（更可靠；local header 在使用数据描述符时可能为 0）。
  const method: number = compression !== 0 ? compression : compressionFromCd;
  const compSize: number = compressedSizeFromCd;

  if (method === 0) {
    // STORED：直接拷贝 uncompressedSize 字节。
    const size: number = uncompressedSizeFromCd;
    const out: Uint8Array = new Uint8Array(size);
    out.set(data.subarray(dataStart, dataStart + size));
    return out;
  }
  if (method === 8) {
    // DEFLATE：raw inflate。
    return inflateRaw(data, dataStart, uncompressedSizeFromCd);
  }
  throw new InvalidFormatError(`ZIP: unsupported compression method ${method}`);
}

/**
 * 读取 ZIP 字节为 ZipView。
 *
 * @param data 原始 .ucx 字节
 * @throws InvalidFormatError 当 offset 0 不是 ZIP 本地文件头魔数，或解析/解压失败时。
 */
export function readZip(data: Uint8Array): ZipView {
  // 要求 ZIP 本地文件头魔数在 offset 0（UCX-FORMAT §1）：拒绝“仅 EOCD”的尾部 ZIP。
  if (
    data.length < 4 ||
    data[0] !== ZIP_MAGIC[0] ||
    data[1] !== ZIP_MAGIC[1] ||
    data[2] !== ZIP_MAGIC[2] ||
    data[3] !== ZIP_MAGIC[3]
  ) {
    throw new InvalidFormatError(
      'not a UCX/ZIP archive: missing PK\\x03\\x04 local file header at offset 0',
    );
  }

  const eocd: EocdInfo | null = findEocd(data);
  if (eocd === null) {
    throw new InvalidFormatError('ZIP: end-of-central-directory not found');
  }

  const entries: Map<string, Uint8Array> = new Map<string, Uint8Array>();
  const order: string[] = [];

  // 遍历中央目录。每条 CD 记录：
  //  0: signature PK\x01\x02 (4)
  //  10: compression (2)
  //  20: compressed size (4) / 24: uncompressed size (4)
  //  28: file name length (2) / 30: extra length (2) / 32: comment length (2)
  //  42: local header offset (4)
  //  46: file name ...
  let p: number = eocd.cdOffset;
  for (let i = 0; i < eocd.cdCount; i++) {
    if (
      p + 46 > data.length ||
      data[p] !== 0x50 ||
      data[p + 1] !== 0x4b ||
      data[p + 2] !== 0x01 ||
      data[p + 3] !== 0x02
    ) {
      throw new InvalidFormatError('ZIP: bad central directory entry signature');
    }
    const compression: number = readU16LE(data, p + 10);
    const compSize: number = readU32LE(data, p + 20);
    const uncompSize: number = readU32LE(data, p + 24);
    const nameLen: number = readU16LE(data, p + 28);
    const extraLen: number = readU16LE(data, p + 30);
    const commentLen: number = readU16LE(data, p + 32);
    const localOffset: number = readU32LE(data, p + 42);

    // [PAIRSIZE-GUARD] 验证 localOffset 在数据范围内，防止越界访问。
    if (localOffset >= data.length) {
      throw new InvalidFormatError('ZIP: local header offset out of bounds');
    }

    const nameBytes: Uint8Array = data.subarray(p + 46, p + 46 + nameLen);
    const name: string = utf8Decode(nameBytes);

    // [P0 Zip-Slip] 对每个条目名执行安全路径验证，
    // 拒绝路径遍历、绝对路径、控制字符、Windows 保留设备名等。
    // 参考 Rust: ucx-types/src/path_safety.rs validate_safe_relative_path()。
    validateSafePath(name);

    const content: Uint8Array = extractEntry(
      data, localOffset, compression, compSize, uncompSize,
    );
    entries.set(name, content);
    order.push(name);

    p = p + 46 + nameLen + extraLen + commentLen;
  }

  return new ZipView(entries, order, data);
}

/**
 * Windows 保留设备名集合（大写）。
 * 这些名字无论大小写、无论是否带扩展名，在 Windows 上都会被解析为设备。
 */
const WINDOWS_RESERVED_NAMES: string[] = [
  'CON', 'PRN', 'AUX', 'NUL',
  'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
  'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9',
];

/**
 * 验证 ZIP 条目路径是安全的相对路径，拒绝可用于 Zip-Slip 攻击的恶意路径。
 *
 * 参考 Rust 实现：ucx-types/src/path_safety.rs:97-170 validate_safe_relative_path()。
 *
 * 拒绝条件：
 * 1. 空字符串
 * 2. 包含 code < 0x20 的控制字符（含 NUL）
 * 3. 包含反斜杠 '\\'
 * 4. 以 '/' 开头（POSIX 绝对路径）
 * 5. 第二个字符是 ':'（Windows 驱动器前缀，如 "C:/"）
 * 6. 任何路径段等于 ".."（父目录遍历）
 * 7. 任何路径段匹配 Windows 保留设备名（大小写不敏感，带或不带扩展名）
 * 8. 任何路径段以 '.' 或 ' ' 结尾（单独的 "." 段允许）
 *
 * @param path ZIP 条目名
 * @throws InvalidFormatError 当路径不安全时
 */
function validateSafePath(path: string): void {
  // 1) 空字符串。
  if (path.length === 0) {
    throw new InvalidFormatError('ZIP: empty entry name');
  }

  // 2) 控制字符（code < 0x20）。
  for (let i = 0; i < path.length; i++) {
    if (path.charCodeAt(i) < 0x20) {
      throw new InvalidFormatError(`ZIP: entry name contains control character: ${path}`);
    }
  }

  // 3) 反斜杠。
  if (path.indexOf('\\') >= 0) {
    throw new InvalidFormatError(`ZIP: entry name contains backslash: ${path}`);
  }

  // 4) 以 '/' 开头（POSIX 绝对路径）。
  if (path.charAt(0) === '/') {
    throw new InvalidFormatError(`ZIP: entry name is absolute path: ${path}`);
  }

  // 5) Windows 驱动器前缀（第二个字符是 ':'，第一个是 ASCII 字母）。
  if (path.length >= 2 && path.charAt(1) === ':') {
    const first: number = path.charCodeAt(0);
    // 'A'=65, 'Z'=90, 'a'=97, 'z'=122
    if ((first >= 65 && first <= 90) || (first >= 97 && first <= 122)) {
      throw new InvalidFormatError(`ZIP: entry name has Windows drive prefix: ${path}`);
    }
  }

  // 逐段验证（以 '/' 分割）。
  const segments: string[] = path.split('/');
  for (let i = 0; i < segments.length; i++) {
    const seg: string = segments[i];
    // 空段（连续 '//'）跳过。
    if (seg.length === 0) {
      continue;
    }

    // 6) 父目录遍历。
    if (seg === '..') {
      throw new InvalidFormatError(`ZIP: entry name contains '..': ${path}`);
    }

    // 7) Windows 保留设备名（大小写不敏感）。
    // 先尝试完整段名，再尝试去掉扩展名后的 stem。
    const upperSeg: string = seg.toUpperCase();
    if (WINDOWS_RESERVED_NAMES.indexOf(upperSeg) >= 0) {
      throw new InvalidFormatError(`ZIP: entry name contains reserved device name: ${path}`);
    }
    // 带扩展名的保留名：如 "CON.txt" -> stem "CON"。
    const dotIdx: number = upperSeg.indexOf('.');
    if (dotIdx >= 0) {
      const stem: string = upperSeg.substring(0, dotIdx);
      if (WINDOWS_RESERVED_NAMES.indexOf(stem) >= 0) {
        throw new InvalidFormatError(`ZIP: entry name contains reserved device name: ${path}`);
      }
    }

    // 8) 段末尾的 '.' 或 ' '（单独的 "." 允许）。
    if (seg !== '.') {
      const lastChar: string = seg.charAt(seg.length - 1);
      if (lastChar === '.' || lastChar === ' ') {
        throw new InvalidFormatError(`ZIP: entry name segment ends with dot or space: ${path}`);
      }
    }
  }
}
