/*
 * SPDX-License-Identifier: MIT
 *
 * archive.ets —— 主门面 UcxArchive 与模块级便捷函数（SDK-API.md §4）。
 *
 * UcxArchive 是 open() 返回的句柄，持有解析后的 codex / structure / manifest，并按需读取条目。
 * 实现 SDK-API §4 的全部只读操作：
 *   open / openBytes / codex / structure / manifest / chapters / listFiles
 *   / readChapter / readChapterText / isChapterEncrypted
 *   / verifyIntegrity / verifySignatures
 *   + 便捷解密 readChapterDecryptedWithKey / ...WithPassphrase。
 * 模块级：isUcxe / decryptWithKey / decryptWithPassphrase / capabilities。
 *
 * 解析流程（open / openBytes）：读字节 → 校验 ZIP magic@0 → 校验 mimetype（第一个条目）
 * → 解析 codex.json / struct.json / MANIFEST.MF。失败抛 InvalidFormat / ParseError。
 *
 * ArkTS 注意：禁 any；解密失败统一折叠为 DecryptionError（不透明，防 oracle）。
 *   open() 依赖 @ohos.file.fs 静态导入（HAR 编译必需），以 HarmonyOS 运行时为前提；
 *   openBytes() 则纯内存、可在任意 ArkTS 运行时工作（推荐在测试 / 非 HarmonyOS 环境用 openBytes）。
 */

import {
  Codex, Structure, Manifest, Chapter,
  IntegrityResult, SignatureResult, Capabilities,
} from './types';
import { MIMETYPE } from './constants';
import { InvalidFormatError, NotFoundError, DecryptionError, IoError } from './errors';
import { readZip, ZipView } from './zip';
import { parseCodex, parseStructure, flattenChapters } from './codex';
import { parseManifest } from './manifest';
import { verifyIntegrity as verifyIntegrityImpl } from './integrity';
import { verifySignatures as verifySignaturesImpl } from './verify';
import {
  isUcxe as isUcxeImpl,
  decryptWithKey as decryptWithKeyImpl,
  decryptWithPassphrase as decryptWithPassphraseImpl,
} from './ucxe';
import { utf8Decode } from './util';
import fileIo from '@ohos.file.fs';

/** 读字节为 UcxArchive 的内部公共逻辑。 */
function buildArchive(data: Uint8Array, filePath: string | undefined): UcxArchive {
  // readZip 内部已校验 ZIP magic@0。
  const zip: ZipView = readZip(data);

  // 校验 mimetype 是第一个条目且内容匹配（trim 容忍尾随换行）。
  if (zip.order.length === 0 || zip.order[0] !== 'mimetype') {
    throw new InvalidFormatError('UCX: first entry must be "mimetype"');
  }
  const mimeBytes: Uint8Array | undefined = zip.get('mimetype');
  if (mimeBytes === undefined) {
    throw new InvalidFormatError('UCX: missing mimetype entry');
  }
  const mime: string = utf8Decode(mimeBytes).trim();
  if (mime !== MIMETYPE) {
    throw new InvalidFormatError(`UCX: unexpected mimetype "${mime}"`);
  }

  // 解析三个必需结构。缺失即 ParseError（codex/struct）或保持 manifest 为空? —— 参考要求必需。
  const codexBytes: Uint8Array | undefined = zip.get('metadata/codex.json');
  const structBytes: Uint8Array | undefined = zip.get('content/struct.json');
  const manifestBytes: Uint8Array | undefined = zip.get('META-INF/MANIFEST.MF');
  if (codexBytes === undefined) {
    throw new InvalidFormatError('UCX: missing metadata/codex.json');
  }
  if (structBytes === undefined) {
    throw new InvalidFormatError('UCX: missing content/struct.json');
  }
  if (manifestBytes === undefined) {
    throw new InvalidFormatError('UCX: missing META-INF/MANIFEST.MF');
  }

  const codex: Codex = parseCodex(codexBytes);
  const structure: Structure = parseStructure(structBytes);
  const manifest: Manifest = parseManifest(manifestBytes);

  return new UcxArchive(data, zip, codex, structure, manifest, filePath);
}

/**
 * UCX 归档句柄。通过 open() / openBytes() 构造，持有已解析的 codex / structure / manifest。
 */
export class UcxArchive {
  /** 原始磁盘字节（Layer 2 验签 / 章节读取需要）。 */
  private readonly data: Uint8Array;
  /** 已解析的 ZIP 视图。 */
  private readonly zip: ZipView;
  /** 作品元数据。 */
  readonly codex: Codex;
  /** 内容结构树。 */
  readonly structure: Structure;
  /** 文件哈希清单。 */
  readonly manifest: Manifest;
  /** 文件路径（openBytes 时为 undefined）。 */
  readonly filePath?: string;

  constructor(
    data: Uint8Array, zip: ZipView, codex: Codex, structure: Structure,
    manifest: Manifest, filePath: string | undefined,
  ) {
    this.data = data;
    this.zip = zip;
    this.codex = codex;
    this.structure = structure;
    this.manifest = manifest;
    if (filePath !== undefined) {
      this.filePath = filePath;
    }
  }

  /** 深度优先扁平化所有叶子章节，按文档顺序。 */
  chapters(): Chapter[] {
    return flattenChapters(this.structure);
  }

  /** 归档内全部条目名（CD / 写入顺序）。 */
  listFiles(): string[] {
    return this.zip.order.slice(0);
  }

  /**
   * 读 content/{file} 的原始字节（可能是 UCXE 密文）。
   * @throws NotFoundError 条目不存在。
   */
  readChapter(file: string): Uint8Array {
    const path: string = `content/${file}`;
    const bytes: Uint8Array | undefined = this.zip.get(path);
    if (bytes === undefined) {
      throw new NotFoundError(`chapter not found: ${path}`);
    }
    return bytes;
  }

  /** readChapter 的 UTF-8 解码便捷方法。 */
  readChapterText(file: string): string {
    return utf8Decode(this.readChapter(file));
  }

  /** content/{file} 前 4 字节是否为 UCXE magic（即是否加密）。 */
  isChapterEncrypted(file: string): boolean {
    const path: string = `content/${file}`;
    const bytes: Uint8Array | undefined = this.zip.get(path);
    if (bytes === undefined) {
      return false;
    }
    return isUcxeImpl(bytes);
  }

  /** 对每个 manifest 条目做 BLAKE3 完整性校验。 */
  verifyIntegrity(): IntegrityResult {
    return verifyIntegrityImpl(this.zip, this.manifest);
  }

  /** 双层 Ed25519 签名验证（Layer1 SF/EC + Layer2 签名块）。 */
  verifySignatures(): SignatureResult {
    return verifySignaturesImpl(this.zip, this.data);
  }

  /**
   * 便捷：读 content/{file} 并用 32 字节直接密钥解密（KDF=None）。
   * @throws NotFoundError 条目不存在；DecryptionError 任何解密失败。
   */
  readChapterDecryptedWithKey(file: string, key: Uint8Array): Uint8Array {
    const ucxe: Uint8Array = this.readChapter(file);
    const pt: Uint8Array | null = decryptWithKeyImpl(ucxe, key);
    if (pt === null) {
      throw new DecryptionError();
    }
    return pt;
  }

  /**
   * 便捷：读 content/{file} 并用口令解密（NFC → KDF → AEAD/CBC）。
   * @throws NotFoundError 条目不存在；DecryptionError 任何解密失败。
   */
  readChapterDecryptedWithPassphrase(file: string, passphrase: string): Uint8Array {
    const ucxe: Uint8Array = this.readChapter(file);
    const pt: Uint8Array | null = decryptWithPassphraseImpl(ucxe, passphrase);
    if (pt === null) {
      throw new DecryptionError();
    }
    return pt;
  }
}

/**
 * 从内存字节打开 UCX 归档（推荐；可在任意 ArkTS 运行时工作）。
 * @throws InvalidFormatError 非 ZIP / mimetype 不符 / 缺必需条目；ParseError JSON/MANIFEST 解析失败。
 */
export function openBytes(data: Uint8Array): UcxArchive {
  return buildArchive(data, undefined);
}

/**
 * 从文件路径打开 UCX 归档（需 HarmonyOS 运行时的 @ohos.file.fs）。
 *
 * 注意：本函数通过静态导入依赖 HarmonyOS 文件系统 API（@ohos.file.fs）。
 * 若运行环境无 @ohos.file.fs（如纯 ArkTS 测试 / Node），请改用 openBytes()。
 *
 * @throws IoError 读取失败；其余同 openBytes。
 */
export async function open(path: string): Promise<UcxArchive> {
  let bytes: Uint8Array;
  try {
    const file = fileIo.openSync(path, fileIo.OpenMode.READ_ONLY);
    try {
      const stat = fileIo.statSync(file.fd);
      const size: number = stat.size;
      const buffer: ArrayBuffer = new ArrayBuffer(size);
      const readLen: number = fileIo.readSync(file.fd, buffer);
      bytes = new Uint8Array(buffer).subarray(0, readLen);
    } finally {
      fileIo.closeSync(file);
    }
  } catch (e) {
    const msg: string = e instanceof Error ? e.message : 'unknown error';
    throw new IoError(`failed to read UCX file: ${msg}`);
  }
  return buildArchive(bytes, path);
}

// ── 模块级解密 / 能力函数（SDK-API §4.6 / §4.7）─────────────────────────────

/** 前 4 字节是否为 UCXE magic。 */
export function isUcxe(data: Uint8Array): boolean {
  return isUcxeImpl(data);
}

/**
 * 用 32 字节直接密钥解密 UCXE 字节（KDF=None；AES-CBC 在此模式被拒）。
 * @throws DecryptionError 任何解密失败（不透明）。
 */
export function decryptWithKey(ucxe: Uint8Array, key: Uint8Array): Uint8Array {
  const pt: Uint8Array | null = decryptWithKeyImpl(ucxe, key);
  if (pt === null) {
    throw new DecryptionError();
  }
  return pt;
}

/**
 * 用口令解密 UCXE 字节（NFC 归一化 → KDF → AEAD/CBC）。
 * @throws DecryptionError 任何解密失败（不透明）。
 */
export function decryptWithPassphrase(ucxe: Uint8Array, passphrase: string): Uint8Array {
  const pt: Uint8Array | null = decryptWithPassphraseImpl(ucxe, passphrase);
  if (pt === null) {
    throw new DecryptionError();
  }
  return pt;
}

/**
 * 返回本 SDK 的能力声明（SDK-API §7）。
 * 本 SDK 为纯 ArkTS 全功能实现，达到 L3（parse + integrity + verify + decrypt）。
 */
export function capabilities(): Capabilities {
  return {
    parse: true,
    integrity: true,
    verifySignatures: true,
    decryptDirectKey: true,
    decryptPassphrase: true,
    algorithms: ['AES-256-GCM', 'AES-256-CBC', 'ChaCha20-Poly1305'],
    kdfs: ['argon2id', 'pbkdf2'],
  };
}
