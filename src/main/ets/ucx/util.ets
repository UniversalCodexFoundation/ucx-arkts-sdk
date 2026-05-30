/*
 * SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * util.ets —— 通用字节 / 编码助手。
 *
 * 这些函数刻意只用纯算法实现（不依赖平台特定 API），以保证跨 HarmonyOS / OpenHarmony
 * 版本与运行时的一致性，并便于人类与 LLM 审阅：
 * - Base64 编解码用纯算法实现（不依赖 util.Base64Helper），保证字节级确定。
 * - UTF-8 编解码用纯算法实现（覆盖 BMP 与代理对），不依赖 TextEncoder 的平台差异。
 * - 常量时间比较用于认证标签校验，避免计时侧信道。
 * - LE/BE 整数读写用于 ZIP / UCXE / 签名块 wire-format。
 *
 * ArkTS 约束：禁 any；所有参数与返回值显式标注类型。
 */

/** standard Base64 字母表（RFC 4648）。 */
const B64_ALPHABET: string =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/** 反查表：char code -> 6-bit 值；非法字符为 -1。 */
const B64_LOOKUP: Int16Array = ((): Int16Array => {
  const t: Int16Array = new Int16Array(256);
  t.fill(-1);
  for (let i = 0; i < B64_ALPHABET.length; i++) {
    t[B64_ALPHABET.charCodeAt(i)] = i;
  }
  return t;
})();

/** 把字节编码为 standard Base64（带 "=" padding，RFC 4648 标准字母表）。 */
export function toBase64(bytes: Uint8Array): string {
  let out: string = '';
  let i: number = 0;
  const len: number = bytes.length;
  for (; i + 3 <= len; i += 3) {
    const n: number = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += B64_ALPHABET.charAt((n >> 18) & 63);
    out += B64_ALPHABET.charAt((n >> 12) & 63);
    out += B64_ALPHABET.charAt((n >> 6) & 63);
    out += B64_ALPHABET.charAt(n & 63);
  }
  const rem: number = len - i;
  if (rem === 1) {
    const n: number = bytes[i] << 16;
    out += B64_ALPHABET.charAt((n >> 18) & 63);
    out += B64_ALPHABET.charAt((n >> 12) & 63);
    out += '==';
  } else if (rem === 2) {
    const n: number = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += B64_ALPHABET.charAt((n >> 18) & 63);
    out += B64_ALPHABET.charAt((n >> 12) & 63);
    out += B64_ALPHABET.charAt((n >> 6) & 63);
    out += '=';
  }
  return out;
}

/** 解码 standard Base64（容忍空白；忽略尾部 padding 校验细节）。 */
export function fromBase64(s: string): Uint8Array {
  // 先统计有效字符数（A-Za-z0-9+/），忽略空白与 '='。
  let end: number = 0;
  for (let i = 0; i < s.length; i++) {
    const c: number = s.charCodeAt(i);
    if (c === 0x3d /* '=' */) break;
    if (c < 256 && B64_LOOKUP[c] >= 0) end++;
  }
  const outLen: number = Math.floor((end * 6) / 8);
  const out: Uint8Array = new Uint8Array(outLen);
  let bits: number = 0;
  let acc: number = 0;
  let oi: number = 0;
  for (let i = 0; i < s.length; i++) {
    const c: number = s.charCodeAt(i);
    if (c === 0x3d) break;
    if (c >= 256) continue;
    const v: number = B64_LOOKUP[c];
    if (v < 0) continue;
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (oi < outLen) {
        out[oi] = (acc >> bits) & 0xff;
        oi++;
      }
    }
  }
  return out;
}

/** 把字符串按 UTF-8 编码为字节（覆盖 BMP 与代理对）。 */
export function utf8Encode(str: string): Uint8Array {
  const out: number[] = [];
  for (let i = 0; i < str.length; i++) {
    let code: number = str.charCodeAt(i);
    // 处理 UTF-16 代理对 -> 单个码点。
    if (code >= 0xd800 && code <= 0xdbff && i + 1 < str.length) {
      const next: number = str.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        code = 0x10000 + ((code - 0xd800) << 10) + (next - 0xdc00);
        i++;
      }
    }
    if (code < 0x80) {
      out.push(code);
    } else if (code < 0x800) {
      out.push(0xc0 | (code >> 6));
      out.push(0x80 | (code & 0x3f));
    } else if (code < 0x10000) {
      out.push(0xe0 | (code >> 12));
      out.push(0x80 | ((code >> 6) & 0x3f));
      out.push(0x80 | (code & 0x3f));
    } else {
      out.push(0xf0 | (code >> 18));
      out.push(0x80 | ((code >> 12) & 0x3f));
      out.push(0x80 | ((code >> 6) & 0x3f));
      out.push(0x80 | (code & 0x3f));
    }
  }
  return new Uint8Array(out);
}

/** 把 UTF-8 字节解码为字符串（非法序列以 U+FFFD 替换，宽容解码）。 */
export function utf8Decode(bytes: Uint8Array): string {
  let out: string = '';
  let i: number = 0;
  const len: number = bytes.length;
  while (i < len) {
    const b0: number = bytes[i];
    let code: number;
    let size: number;
    if (b0 < 0x80) {
      code = b0;
      size = 1;
    } else if ((b0 & 0xe0) === 0xc0) {
      code = b0 & 0x1f;
      size = 2;
    } else if ((b0 & 0xf0) === 0xe0) {
      code = b0 & 0x0f;
      size = 3;
    } else if ((b0 & 0xf8) === 0xf0) {
      code = b0 & 0x07;
      size = 4;
    } else {
      // 非法起始字节。
      out += String.fromCharCode(0xfffd);
      i++;
      continue;
    }
    if (i + size > len) {
      out += String.fromCharCode(0xfffd);
      break;
    }
    let ok: boolean = true;
    for (let k = 1; k < size; k++) {
      const bk: number = bytes[i + k];
      if ((bk & 0xc0) !== 0x80) {
        ok = false;
        break;
      }
      code = (code << 6) | (bk & 0x3f);
    }
    if (!ok) {
      out += String.fromCharCode(0xfffd);
      i++;
      continue;
    }
    i += size;
    if (code <= 0xffff) {
      out += String.fromCharCode(code);
    } else {
      // 拆成代理对。
      code -= 0x10000;
      out += String.fromCharCode(0xd800 + (code >> 10));
      out += String.fromCharCode(0xdc00 + (code & 0x3ff));
    }
  }
  return out;
}

/** 拼接多个字节块。 */
export function concatBytes(arrays: Uint8Array[]): Uint8Array {
  let total: number = 0;
  for (let i = 0; i < arrays.length; i++) {
    total += arrays[i].length;
  }
  const out: Uint8Array = new Uint8Array(total);
  let off: number = 0;
  for (let i = 0; i < arrays.length; i++) {
    out.set(arrays[i], off);
    off += arrays[i].length;
  }
  return out;
}

/** 字节相等（普通比较，用于非敏感场景，如证书 DER 比对）。 */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

/**
 * 常量时间字节相等比较。
 * 用于认证标签（HMAC / GCM tag）校验，避免按字节短路造成的计时侧信道。
 * 长度不同直接返回 false（长度本身不是机密）。
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff: number = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/** 把字节编码为小写 hex 字符串。 */
export function toHex(bytes: Uint8Array): string {
  let out: string = '';
  for (let i = 0; i < bytes.length; i++) {
    const v: number = bytes[i];
    out += (v >> 4).toString(16);
    out += (v & 0x0f).toString(16);
  }
  return out;
}

/** 写小端 u32 到一个 4 字节数组。 */
export function u32le(n: number): Uint8Array {
  const b: Uint8Array = new Uint8Array(4);
  b[0] = n & 0xff;
  b[1] = (n >>> 8) & 0xff;
  b[2] = (n >>> 16) & 0xff;
  b[3] = (n >>> 24) & 0xff;
  return b;
}

/** 写大端 u32 到一个 4 字节数组（分块 nonce 用）。 */
export function u32be(n: number): Uint8Array {
  const b: Uint8Array = new Uint8Array(4);
  b[0] = (n >>> 24) & 0xff;
  b[1] = (n >>> 16) & 0xff;
  b[2] = (n >>> 8) & 0xff;
  b[3] = n & 0xff;
  return b;
}

/** 读小端 u16。 */
export function readU16LE(b: Uint8Array, o: number): number {
  return b[o] | (b[o + 1] << 8);
}

/** 读小端 u32（返回非负数）。 */
export function readU32LE(b: Uint8Array, o: number): number {
  return (
    (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0
  );
}

/** 读小端 u64（返回 JS number；UCX 实际值远小于 2^53，安全）。 */
export function readU64LE(b: Uint8Array, o: number): number {
  const lo: number = readU32LE(b, o);
  const hi: number = readU32LE(b, o + 4);
  return hi * 0x100000000 + lo;
}

/** 取子数组的拷贝（避免共享底层 buffer 的别名问题）。 */
export function sliceCopy(b: Uint8Array, start: number, end: number): Uint8Array {
  const e: number = end < b.length ? end : b.length;
  const s: number = start < 0 ? 0 : start;
  const out: Uint8Array = new Uint8Array(e - s);
  out.set(b.subarray(s, e));
  return out;
}
