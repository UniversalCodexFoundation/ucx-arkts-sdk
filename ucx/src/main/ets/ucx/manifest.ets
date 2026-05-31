/*
 * SPDX-License-Identifier: MIT
 *
 * manifest.ets —— META-INF/MANIFEST.MF 文本格式解析（UCX-FORMAT §3）。
 *
 * 格式为 RFC-822-ish：用空行（"\n\n"）分节，行形如 "Key: Value"
 * （注意：参考解析器按**第一个 ": "（冒号+空格）**切分）。每行以 "\n" 结尾。
 *
 * - 主节（第一节）：Manifest-Version / UCX-Version / Created-By? / Hash-Algorithm。
 * - 后续每节描述一个文件：Name / Size / {ALGO}-Digest，可选 Encrypted / Original-Size。
 *
 * 摘要值是 **Base64-standard(padded)** 的原始哈希，不是 hex（§3.2，load-bearing）。
 *
 * ArkTS 注意：禁 any；用 Map<string,string> 表示一节的 key->value。
 */

import { Manifest, ManifestEntry } from './types';
import { ParseError } from './errors';
import { SUPPORTED_UCX_MAJOR } from './constants';
import { utf8Decode } from './util';

/** 把一节文本解析为 key->value 映射。按第一个 ": " 切分（与参考实现一致）。 */
function parseSection(section: string): Map<string, string> {
  const map: Map<string, string> = new Map<string, string>();
  const lines: string[] = section.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line: string = lines[i];
    if (line.length === 0) {
      continue;
    }
    const idx: number = line.indexOf(': ');
    if (idx < 0) {
      continue;
    }
    const key: string = line.substring(0, idx);
    const value: string = line.substring(idx + 2);
    map.set(key, value);
  }
  return map;
}

/** 把文本按一个或多个空行分节，过滤纯空白节。 */
function splitSections(text: string): string[] {
  // 归一化 CRLF -> LF（参考写入用 LF）。
  const normalized: string = text.split('\r\n').join('\n');
  // 用“连续空行”分节。手写扫描以避免正则在 ArkTS 上的行为差异。
  const out: string[] = [];
  const rawParts: string[] = normalized.split('\n\n');
  let current: string = '';
  for (let i = 0; i < rawParts.length; i++) {
    const part: string = rawParts[i];
    if (part.trim().length === 0) {
      // 连续空行：若当前累积非空则收尾。
      if (current.trim().length > 0) {
        out.push(current);
        current = '';
      }
      continue;
    }
    if (current.length > 0) {
      out.push(current);
    }
    current = part;
  }
  if (current.trim().length > 0) {
    out.push(current);
  }
  return out;
}

/** 解析 MANIFEST.MF 文本字节为 Manifest 结构。 */
export function parseManifest(bytes: Uint8Array): Manifest {
  const text: string = utf8Decode(bytes);
  const rawSections: string[] = splitSections(text);

  if (rawSections.length === 0) {
    throw new ParseError('MANIFEST.MF is empty or malformed');
  }

  const main: Map<string, string> = parseSection(rawSections[0]);

  const manifestVersion: string | undefined = main.get('Manifest-Version');
  const ucxVersion: string | undefined = main.get('UCX-Version');
  const hashAlgorithm: string | undefined = main.get('Hash-Algorithm');

  if (manifestVersion === undefined) {
    throw new ParseError('MANIFEST.MF: missing Manifest-Version');
  }
  if (ucxVersion === undefined) {
    throw new ParseError('MANIFEST.MF: missing UCX-Version');
  }
  if (hashAlgorithm === undefined) {
    throw new ParseError('MANIFEST.MF: missing Hash-Algorithm');
  }

  // 拒绝 MAJOR > 1（UCX-FORMAT §3.1）。
  const majorStr: string = ucxVersion.split('.')[0];
  const major: number = parseInt(majorStr, 10);
  if (!Number.isFinite(major) || major > SUPPORTED_UCX_MAJOR) {
    throw new ParseError(
      `unsupported UCX-Version ${ucxVersion} (major > ${SUPPORTED_UCX_MAJOR})`,
    );
  }

  // 摘要 header 名为 "{ALGO}-Digest"，如 "BLAKE3-Digest"。
  const digestKey: string = `${hashAlgorithm}-Digest`;

  const entries: ManifestEntry[] = [];
  for (let i = 1; i < rawSections.length; i++) {
    const sec: Map<string, string> = parseSection(rawSections[i]);
    const name: string | undefined = sec.get('Name');
    const sizeStr: string | undefined = sec.get('Size');
    const digest: string | undefined = sec.get(digestKey);
    if (name === undefined || sizeStr === undefined || digest === undefined) {
      // 该节不是合法文件条目，跳过（容错于扩展节）。
      continue;
    }
    const size: number = parseInt(sizeStr, 10);
    const encryptedStr: string | undefined = sec.get('Encrypted');
    const encrypted: boolean = encryptedStr === 'true';
    const originalSizeStr: string | undefined = sec.get('Original-Size');

    const entry: ManifestEntry = {
      name: name,
      size: Number.isFinite(size) ? size : 0,
      digest: digest,
      encrypted: encrypted,
    };
    if (originalSizeStr !== undefined) {
      const os: number = parseInt(originalSizeStr, 10);
      if (Number.isFinite(os)) {
        entry.originalSize = os;
      }
    }
    entries.push(entry);
  }

  const manifest: Manifest = {
    manifestVersion: manifestVersion,
    ucxVersion: ucxVersion,
    hashAlgorithm: hashAlgorithm,
    entries: entries,
  };
  const createdBy: string | undefined = main.get('Created-By');
  if (createdBy !== undefined) {
    manifest.createdBy = createdBy;
  }
  return manifest;
}
