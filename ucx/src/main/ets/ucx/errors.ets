/*
 * SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * errors.ets —— 统一错误模型（Error Model），对应 SDK-API.md §5。
 *
 * 所有 SDK 暴露同一套错误“类别”，各语言映射到惯用机制。ArkTS 用异常类层级：
 * 所有错误继承自 UcxError，便于 `instanceof UcxError` 统一捕获，也可按子类细分。
 *
 * ⚠️ 关键安全约束：解密失败必须统一折叠为不透明的 DecryptionError（固定文案），
 * 不泄露具体失败原因（防 padding/auth oracle，对齐参考实现
 * ucx-crypto/src/lib.rs:138-152）。I/O 错误可以透传为 IoError。
 *
 * ArkTS 注意：Error 子类需正确设置原型链；与 TS 一致用 Object.setPrototypeOf。
 */

/** SDK-API.md §5 的稳定错误类别名（跨语言一致）。 */
export type UcxErrorCategory =
  | 'InvalidFormat'
  | 'NotFound'
  | 'ParseError'
  | 'Unsupported'
  | 'DecryptionError'
  | 'IoError';

/** SDK 所有错误的基类。`category` 字段给出 SDK-API.md §5 的稳定类别名。 */
export class UcxError extends Error {
  /** 稳定的错误类别标识，跨语言一致（如 "InvalidFormat"）。 */
  public readonly category: UcxErrorCategory;

  constructor(category: UcxErrorCategory, message: string) {
    super(message);
    this.name = `UcxError(${category})`;
    this.category = category;
    // 维持原型链（ArkTS / TS 编译到旧目标时的惯例修正）。
    Object.setPrototypeOf(this, UcxError.prototype);
  }
}

/** 非 ZIP、mimetype 不符、UCX MAJOR>1、UCXE magic/version 非法。 */
export class InvalidFormatError extends UcxError {
  constructor(message: string) {
    super('InvalidFormat', message);
    Object.setPrototypeOf(this, InvalidFormatError.prototype);
  }
}

/** 请求的条目 / 章节不存在。 */
export class NotFoundError extends UcxError {
  constructor(message: string) {
    super('NotFound', message);
    Object.setPrototypeOf(this, NotFoundError.prototype);
  }
}

/** JSON / MANIFEST 解析失败。 */
export class ParseError extends UcxError {
  constructor(message: string) {
    super('ParseError', message);
    Object.setPrototypeOf(this, ParseError.prototype);
  }
}

/** 该 SDK 未实现的算法 / KDF / 能力（对应 §7 未实现项）。 */
export class UnsupportedError extends UcxError {
  constructor(message: string) {
    super('Unsupported', message);
    Object.setPrototypeOf(this, UnsupportedError.prototype);
  }
}

/**
 * 任何解密失败的统一不透明错误。
 *
 * 安全要求：文案固定，**绝不**包含触发原因（认证失败 / 头部非法 / KDF 越界 / padding
 * 错误等都折叠成同一条消息），以避免给攻击者提供解密 oracle。
 */
export class DecryptionError extends UcxError {
  constructor() {
    // 固定、不透明的文案。
    super('DecryptionError', 'decryption failed');
    Object.setPrototypeOf(this, DecryptionError.prototype);
  }
}

/** 文件读写失败。I/O 错误允许透传细节。 */
export class IoError extends UcxError {
  constructor(message: string) {
    super('IoError', message);
    Object.setPrototypeOf(this, IoError.prototype);
  }
}
