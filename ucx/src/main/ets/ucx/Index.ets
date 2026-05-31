/*
 * SPDX-License-Identifier: MIT
 *
 * Index.ets —— Unicodex UCX ArkTS SDK 的公开 API 统一导出入口。
 *
 * 对接 SDK-API.md：
 *   §2 命名规范：方法/字段 camelCase，类型 PascalCase，常量 SCREAMING_SNAKE。
 *   §3 数据模型：Codex / Structure / Manifest / Chapter / 结果类型 / 枚举。
 *   §4 公开操作：UcxArchive 的方法 + 模块级 isUcxe / decryptWithKey / decryptWithPassphrase
 *               / capabilities；以及 open / openBytes。
 *   §6 量化常量：MIMETYPE / *_MAGIC / ALGO_* / KDF_* / 长度 / 默认参数 / 签名常量。
 *   §5 错误模型：UcxError 及其子类。
 *
 * 使用方应只从本文件 import，内部模块布局可自由演进。HAR 包的入口由 oh-package.json5
 * 的 "main" 指向本文件。
 */

// ── §4 / 主门面：UcxArchive 与打开 / 模块级解密 / 能力 ──────────────────────
export {
  UcxArchive,
  open,
  openBytes,
  isUcxe,
  decryptWithKey,
  decryptWithPassphrase,
  capabilities,
} from './archive';

// ── §3 数据模型（类型与枚举）───────────────────────────────────────────────
export {
  Codex,
  Title,
  Creator,
  Identifier,
  Series,
  Publisher,
  Description,
  Rights,
  Dates,
  Rating,
  FileVersion,
  Structure,
  StructureNode,
  Chapter,
  Manifest,
  ManifestEntry,
  IntegrityResult,
  IntegrityEntry,
  SignatureResult,
  SignatureStatus,
  Signer,
  Capabilities,
  JsonValue,
  JsonObject,
} from './types';

// ── §5 错误模型 ─────────────────────────────────────────────────────────────
export {
  UcxError,
  UcxErrorCategory,
  InvalidFormatError,
  NotFoundError,
  ParseError,
  UnsupportedError,
  DecryptionError,
  IoError,
} from './errors';

// ── §6 量化常量（SCREAMING_SNAKE，跨语言同名）───────────────────────────────
export {
  MIMETYPE,
  ZIP_MAGIC,
  UCXE_MAGIC,
  UCXE_FORMAT_VERSION,
  SUPPORTED_UCX_MAJOR,
  ALGO_AES_256_GCM,
  ALGO_AES_256_CBC,
  ALGO_CHACHA20_POLY1305,
  KDF_NONE,
  KDF_ARGON2ID,
  KDF_PBKDF2_HMAC_SHA256,
  AEAD_NONCE_LEN,
  CBC_IV_LEN,
  GCM_TAG_LEN,
  CHACHA_TAG_LEN,
  CBC_MAC_LEN,
  SALT_LEN,
  ARGON2_VERSION,
  ARGON2_DEFAULT_MEM_KIB,
  ARGON2_DEFAULT_TIME,
  ARGON2_DEFAULT_PARALLELISM,
  PBKDF2_DEFAULT_ITERS,
  CHUNK_THRESHOLD,
  CHUNK_SIZE,
  SIG_ALGO_ED25519_BLAKE3,
  ED25519_SIG_LEN,
  ED25519_PUBKEY_LEN,
  ED25519_SPKI_OID,
  L2_BLOCK_MAGIC,
  L2_PAIR_ID,
  L2_CHUNK_PREFIX,
  L2_TOP_PREFIX,
} from './constants';
