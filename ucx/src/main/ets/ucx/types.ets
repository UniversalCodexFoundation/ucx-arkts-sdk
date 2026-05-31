/*
 * SPDX-License-Identifier: MIT
 *
 * types.ets —— 数据模型（Data Model），对应 SDK-API.md §3。
 *
 * 字段名按 §3（语言中立 camelCase，ArkTS 直接采用）。所有结构提供 `raw`
 * 字段（原始已解析 JSON，类型为 JsonObject），便于前向兼容未建模字段。
 * 可选字段用 ArkTS 的 `?`。
 *
 * 解析永不失败于未知字段：缺失可选字段为 undefined，不报错（见 codex.ets）。
 *
 * ArkTS 约束：禁用 any/unknown；类型别名禁止循环引用。
 * JSON 的”任意值”用 Object | null 表达（ArkTS 的 Object 涵盖 string/number/boolean/Array/Record 等全部非 null 值）。
 * 对象用 JsonObject（= Record<string, JsonValue>），数组用 (Object | null)[]。
 * 运行时类型检查由 codex.ets 的守卫函数（typeof / Array.isArray）保证安全。
 */

// ── JSON 值的静态类型表达（替代 TS 的 unknown）─────────────────────────────

/**
 * 任意 JSON 值的静态类型。
 * ArkTS 不允许递归类型别名（JsonValue[] / JsonObject 会形成循环引用），
 * 因此用 Object | null 替代递归联合：Object 涵盖 string / number / boolean /
 * Array / Record 等全部非 null JSON 值。
 */
export type JsonValue = Object | null;

/** JSON 对象（字符串键到 JsonValue 的映射）。 */
export type JsonObject = Record<string, JsonValue>;

// ── Codex（metadata/codex.json）────────────────────────────────────────────

/** 作品标题信息。 */
export interface Title {
  /** 主标题（必填）。 */
  main: string;
  subtitle?: string;
  original?: string;
  short?: string;
}

/** 创作者（作者 / 译者 / 插画师等）。 */
export interface Creator {
  /** 姓名（必填）。 */
  name: string;
  /** 角色（必填），如 "author"、"translator"。 */
  role: string;
  /** 关联到 META-INF/signatures/{SIGNER} 的签名者 id。 */
  signatureRef?: string;
}

/** 标识符集合。 */
export interface Identifier {
  /** UCX 主标识，形如 "urn:ucx:{uuidv4}"（必填）。 */
  ucxId: string;
  isbn?: string;
  issn?: string;
  doi?: string;
  /** 自定义标识符映射。 */
  custom?: Record<string, string>;
}

/** 系列信息。 */
export interface Series {
  name: string;
  index?: number;
  total?: number;
}

/** 出版方信息。 */
export interface Publisher {
  name: string;
  imprint?: string;
  signatureRef?: string;
}

/** 简介（短/长）。 */
export interface Description {
  short?: string;
  long?: string;
}

/** 权利声明。 */
export interface Rights {
  statement?: string;
  license?: string;
}

/** 日期（ISO-8601）。 */
export interface Dates {
  created?: string;
  published?: string;
  modified?: string;
}

/** 分级信息。 */
export interface Rating {
  system: string;
  value: string;
}

/** 文件版本信息。 */
export interface FileVersion {
  version?: string;
  revision?: number;
  releasedAt?: string;
  changelog?: string;
}

/** 作品元数据（codex.json 解析结果）。 */
export interface Codex {
  /** = identifier.ucxId，形如 "urn:ucx:{uuidv4}"。 */
  ucxId: string;
  title: Title;
  /** 创作者列表，≥1。 */
  creators: Creator[];
  /** BCP-47 语言标签，如 "en"、"zh-CN"。 */
  language: string;
  series?: Series;
  publisher?: Publisher;
  genre?: string[];
  tags?: string[];
  /** ongoing | completed | hiatus | abandoned | draft。 */
  status?: string;
  wordCount?: number;
  description?: Description;
  rights?: Rights;
  /** ISO-8601 日期。 */
  dates?: Dates;
  cover?: string;
  rating?: Rating;
  fileVersion?: FileVersion;
  identifier: Identifier;
  /** = codex.json 的 "version" 字段（元数据 schema 版本）。 */
  schemaVersion: string;
  /** 原始已解析 JSON，用于前向兼容。 */
  raw: JsonObject;
}

// ── Structure（content/struct.json）────────────────────────────────────────

/**
 * 结构树节点（递归）。
 * - leaf：有 `file`、无 `children`。
 * - container：有 `children`、无 `file`。
 */
export interface StructureNode {
  /** 标题（唯一必填字段）。 */
  title: string;
  /** 叶子路径，相对 content/，如 "chapter-001.md"。与 children 互斥。 */
  file?: string;
  /** 子节点；container 才有。与 file 互斥。 */
  children?: StructureNode[];
  /** JSON key 为 "type"（Rust 字段 node_type）。 */
  type?: string;
  id?: string;
  name?: string;
  style?: string;
  /** 加密描述对象，仅 leaf 有意义（见 UCX-FORMAT §4.2）。原样保留。 */
  encryption?: JsonObject;
}

/** 内容结构树（struct.json 解析结果）。 */
export interface Structure {
  /** = struct.json 的 "version" 字段。 */
  schemaVersion: string;
  nodes: StructureNode[];
  raw: JsonObject;
}

/** chapters() 扁平化后的叶子章节。 */
export interface Chapter {
  title: string;
  /** 相对 content/ 的路径，如 "chapter-001.md"。 */
  file: string;
  /** 归档内绝对路径 "content/{file}"。 */
  path: string;
}

// ── Manifest（META-INF/MANIFEST.MF）─────────────────────────────────────────

/** 单个 manifest 条目。 */
export interface ManifestEntry {
  /** 归档相对路径。 */
  name: string;
  /** 存储（密文，若加密）字节数。 */
  size: number;
  /** Base64-standard(padded) 的原始 BLAKE3 哈希；**NOT hex**。 */
  digest: string;
  /** 是否为加密条目（默认 false）。 */
  encrypted: boolean;
  /** 仅加密条目：明文大小。 */
  originalSize?: number;
}

/** 文件哈希清单（MANIFEST.MF 解析结果）。 */
export interface Manifest {
  manifestVersion: string;
  ucxVersion: string;
  createdBy?: string;
  /** "BLAKE3" | "SHA256" | "SHA512"（参考实现只产出 BLAKE3）。 */
  hashAlgorithm: string;
  entries: ManifestEntry[];
}

// ── 完整性结果 ─────────────────────────────────────────────────────────────

/** 单条目完整性结果。 */
export interface IntegrityEntry {
  name: string;
  /** manifest 中记录的 Base64 digest。 */
  expected: string;
  /** 实际重算的 Base64 digest（条目缺失时为 ""）。 */
  actual: string;
  valid: boolean;
}

/** verifyIntegrity() 的结果。 */
export interface IntegrityResult {
  /** 所有条目均通过才为 true。 */
  valid: boolean;
  entries: IntegrityEntry[];
}

// ── 签名结果 ───────────────────────────────────────────────────────────────

/**
 * 签名状态枚举，严格遵循 UCX-FORMAT §6 状态表。
 * 注意：API 契约枚举名为 VERIFIED（对应参考实现的 Valid 状态）。
 */
export enum SignatureStatus {
  UNSIGNED = 'UNSIGNED',
  VERIFIED = 'VERIFIED',
  VALID_WITH_WARNINGS = 'VALID_WITH_WARNINGS',
  INVALID = 'INVALID',
}

/** 单个签名者的验证结果。 */
export interface Signer {
  /** 来自 META-INF/signatures/{SIGNER}.SF 的文件名 stem。 */
  signerId: string;
  subjectCn?: string;
  /** lowercase-hex BLAKE3(cert_der)，64 hex。 */
  fingerprint?: string;
  /** "self-signed" | "ca-issued"。 */
  certType?: string;
  layer1Valid: boolean;
  layer2Valid: boolean;
}

/** verifySignatures() 的结果。 */
export interface SignatureResult {
  status: SignatureStatus;
  layer1Present: boolean;
  layer1Valid: boolean;
  layer2Present: boolean;
  layer2Valid: boolean;
  signers: Signer[];
}

// ── 能力声明 ───────────────────────────────────────────────────────────────

/** capabilities() 返回的能力布尔集（对应 SDK-API.md §7）。 */
export interface Capabilities {
  /** 恒 true（解析能力）。 */
  parse: boolean;
  /** BLAKE3 完整性校验可用。 */
  integrity: boolean;
  /** Ed25519 双层签名验证可用。 */
  verifySignatures: boolean;
  /** UCXE 直接密钥解密可用。 */
  decryptDirectKey: boolean;
  /** UCXE 口令解密可用。 */
  decryptPassphrase: boolean;
  /** 实际支持的对称算法子集。 */
  algorithms: string[];
  /** 实际支持的 KDF 子集。 */
  kdfs: string[];
}
