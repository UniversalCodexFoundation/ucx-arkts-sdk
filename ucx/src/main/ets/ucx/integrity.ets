/*
 * SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * integrity.ets —— BLAKE3 完整性校验（UCX-FORMAT §5）。
 *
 * 对每个 manifest 条目：
 *   1. 读取条目的解压字节。
 *   2. 计算 BLAKE3 -> 32 字节原始哈希。
 *   3. 编码为 standard Base64（带 padding）。
 *   4. 与 manifest 中的 digest 字符串比较，相等即有效。
 *
 * 摘要无 salt / 前缀 / 长度框定，是对“确切解压字节”的纯 BLAKE3。
 *
 * ArkTS 注意：BLAKE3 由自带纯实现 blake3.ets 提供。
 */

import { blake3 } from './blake3';
import { ZipView } from './zip';
import { Manifest, IntegrityResult, IntegrityEntry } from './types';
import { toBase64 } from './util';

/** 计算字节的 BLAKE3 并编码为 standard Base64（padded）。 */
export function blake3Base64(bytes: Uint8Array): string {
  return toBase64(blake3(bytes));
}

/** 对一个 ZIP 视图按 manifest 做完整性校验。 */
export function verifyIntegrity(zip: ZipView, manifest: Manifest): IntegrityResult {
  const entries: IntegrityEntry[] = [];
  let allValid: boolean = true;

  for (let i = 0; i < manifest.entries.length; i++) {
    const me = manifest.entries[i];
    const data: Uint8Array | undefined = zip.get(me.name);
    if (data === undefined) {
      // 条目缺失：算作失败（actual 空）。
      entries.push({ name: me.name, expected: me.digest, actual: '', valid: false });
      allValid = false;
      continue;
    }
    const actual: string = blake3Base64(data);
    const valid: boolean = actual === me.digest;
    if (!valid) {
      allValid = false;
    }
    entries.push({ name: me.name, expected: me.digest, actual: actual, valid: valid });
  }

  return { valid: allValid, entries: entries };
}
