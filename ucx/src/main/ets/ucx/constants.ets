/*
 * SPDX-License-Identifier: MIT
 *
 * constants.ets —— Unicodex UCX 格式的量化常量（Quantitative constants）。
 *
 * 本文件暴露 SDK-API.md §6 要求的全部同名常量。数值均取自 UCX-FORMAT.md
 * （Appendix A，已对参考 Rust 实现逐行核验）。所有 SDK 必须暴露这些常量，
 * 仅命名大小写按各语言惯例本地化。ArkTS 采用 SCREAMING_SNAKE_CASE。
 *
 * 这些常量是 wire-format 的“魔法数字”，集中放置便于人类与 LLM 审阅，
 * 防止在解析/解密代码里出现散落的硬编码值。
 *
 * 注意：ArkTS 是 TypeScript 的受限子集（禁 any、禁动态类型），所有导出常量
 * 均显式标注类型。字节常量用 Uint8Array（不可变约定由调用方保证）。
 */

/** ZIP 容器的 mimetype 字符串。必须是归档第一个条目、STORED（不压缩），28 字节，无尾随换行。 */
export const MIMETYPE: string = 'application/vnd.unicodex+zip';

/** ZIP 本地文件头魔数（PK\x03\x04），必须出现在文件 offset 0。 */
export const ZIP_MAGIC: Uint8Array = new Uint8Array([0x50, 0x4b, 0x03, 0x04]);

/** UCXE 加密容器魔数（"UCXE"），出现在被加密条目的 offset 0。 */
export const UCXE_MAGIC: Uint8Array = new Uint8Array([0x55, 0x43, 0x58, 0x45]);

/** UCXE 头部 format version 字段的合法值。解析器拒绝其它值。 */
export const UCXE_FORMAT_VERSION: number = 0x01;

/** 解析器接受的 UCX 主版本上限；MAJOR > 1 的归档被拒绝。 */
export const SUPPORTED_UCX_MAJOR: number = 1;

// ── 对称算法 ID（UCXE 头部第 6 字节，offset 5）─────────────────────────────
/** AES-256-GCM：nonce 12 字节，tag 16 字节。 */
export const ALGO_AES_256_GCM: number = 0x01;
/** AES-256-CBC + HMAC-SHA256（Encrypt-then-MAC）：iv 16 字节，mac 32 字节。 */
export const ALGO_AES_256_CBC: number = 0x02;
/** ChaCha20-Poly1305：nonce 12 字节，tag 16 字节。 */
export const ALGO_CHACHA20_POLY1305: number = 0x03;

// ── KDF ID（UCXE 头部第 7 字节，offset 6）──────────────────────────────────
/** KDF=None：密钥直接给出（无参数块，0 字节）。 */
export const KDF_NONE: number = 0x00;
/** Argon2id：参数块 12 字节 = mem_kib:u32 ‖ time:u32 ‖ par:u32（LE）。 */
export const KDF_ARGON2ID: number = 0x01;
/** PBKDF2-HMAC-SHA256：参数块 4 字节 = iterations:u32（LE）。 */
export const KDF_PBKDF2_HMAC_SHA256: number = 0x02;

// ── 长度常量 ───────────────────────────────────────────────────────────────
/** AEAD（GCM / ChaCha20）的 nonce 长度。 */
export const AEAD_NONCE_LEN: number = 12;
/** AES-CBC 的 IV 长度。 */
export const CBC_IV_LEN: number = 16;
/** AES-256-GCM 的认证 tag 长度。 */
export const GCM_TAG_LEN: number = 16;
/** ChaCha20-Poly1305 的认证 tag 长度。 */
export const CHACHA_TAG_LEN: number = 16;
/** AES-CBC 的 HMAC-SHA256 “tag” 长度。 */
export const CBC_MAC_LEN: number = 32;
/** 解密路径要求 salt 恰好为该长度（口令模式）。 */
export const SALT_LEN: number = 16;

// ── KDF 默认参数与边界 ─────────────────────────────────────────────────────
/** Argon2 版本：v19 = 0x13。 */
export const ARGON2_VERSION: number = 0x13;
/** Argon2id 默认内存（KiB）= 64 MiB；边界 19456..4194304。 */
export const ARGON2_DEFAULT_MEM_KIB: number = 65536;
/** Argon2id 默认时间代价（迭代轮数）；边界 2..100。 */
export const ARGON2_DEFAULT_TIME: number = 3;
/** Argon2id 默认并行度；边界 ≥1。 */
export const ARGON2_DEFAULT_PARALLELISM: number = 4;
/** PBKDF2-HMAC-SHA256 默认迭代次数；边界 100000..10000000。 */
export const PBKDF2_DEFAULT_ITERS: number = 600000;

// Argon2id 参数解析边界（refuse out-of-range，见 UCX-FORMAT §8.1）
export const ARGON2_MIN_MEM_KIB: number = 19456;
export const ARGON2_MAX_MEM_KIB: number = 4194304;
export const ARGON2_MIN_TIME: number = 2;
export const ARGON2_MAX_TIME: number = 100;
export const ARGON2_MIN_PARALLELISM: number = 1;
/** Argon2id 并行度上限（参考 Argon2 C 库 uint8 限制，同时约束移动端内存）。 */
export const ARGON2_MAX_PARALLELISM: number = 255;
// PBKDF2 迭代边界（见 UCX-FORMAT §8.2）
export const PBKDF2_MIN_ITERS: number = 100000;
export const PBKDF2_MAX_ITERS: number = 10000000;

// ── 分块（大文件）──────────────────────────────────────────────────────────
/** 明文长度严格 > 该阈值（64 MiB）才启用分块。 */
export const CHUNK_THRESHOLD: number = 67108864;
/** 每个明文块的大小（1 MiB），最后一块可能更小。 */
export const CHUNK_SIZE: number = 1048576;
// 子 nonce = base_nonce[0..8] ‖ u32_be(chunk_index)

// ── 签名 ───────────────────────────────────────────────────────────────────
/** 两层签名共用的算法 ID：0x0001 = Ed25519 + BLAKE3。 */
export const SIG_ALGO_ED25519_BLAKE3: number = 0x0001;
/** Ed25519 签名长度。 */
export const ED25519_SIG_LEN: number = 64;
/** Ed25519 原始公钥长度。 */
export const ED25519_PUBKEY_LEN: number = 32;
/** Ed25519 在 X.509 SubjectPublicKeyInfo 中的 OID。 */
export const ED25519_SPKI_OID: string = '1.3.101.112';
/**
 * Layer 2 UCX 签名块魔数（含尾随 NUL），16 字节。
 * 重要：最后一个字节是 NUL（0x00），不是空格。为避免字符串字面量里嵌入
 * NUL 造成的歧义，这里用显式字节数组给出权威值（verify.ets 直接比对该数组）。
 * 对应 ASCII："U","C","X"," ","S","i","g"," ","B","l","o","c","k"," ","1",NUL。
 */
export const L2_BLOCK_MAGIC: Uint8Array = new Uint8Array([
  0x55, 0x43, 0x58, 0x20, 0x53, 0x69, 0x67, 0x20,
  0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x31, 0x00,
]);
/** Layer 2 键值对 ID（PAIR_ID_UCX_SIG_V1）。 */
export const L2_PAIR_ID: number = 0x55435801;
/** Layer 2 分块摘要的 chunk 前缀字节。 */
export const L2_CHUNK_PREFIX: number = 0xa5;
/** Layer 2 分块摘要的 top 前缀字节。 */
export const L2_TOP_PREFIX: number = 0x5a;
/** Layer 2 分块大小（与 UCXE 分块同为 1 MiB，但用途不同：覆盖 ZIP 原始字节）。 */
export const L2_CHUNK_SIZE: number = 1048576;
