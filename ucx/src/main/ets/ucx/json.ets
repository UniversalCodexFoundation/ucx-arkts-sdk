/*
 * SPDX-License-Identifier: MIT
 *
 * json.ets —— 自带的最小 JSON 解析器，返回强类型 JsonValue（避免 ArkTS 对
 * 平台 JSON.parse 返回类型的处理摩擦，并保证宽松反序列化的确定行为）。
 *
 * 支持完整 JSON 语法（对象/数组/字符串/数字/true/false/null，含转义与 \uXXXX）。
 * 数字一律解析为 number（double）。这满足 UCX codex/struct.json 的全部需要。
 *
 * ArkTS 注意：禁 any/unknown；用 JsonValue 联合类型承载任意 JSON 取值。
 */

import { JsonValue, JsonObject } from './types';
import { ParseError } from './errors';

/** 一个带位置游标的 JSON 解析器。 */
class JsonParser {
  private s: string;
  private i: number;
  private n: number;

  constructor(s: string) {
    this.s = s;
    this.i = 0;
    this.n = s.length;
  }

  /** 解析整个文本为一个 JsonValue。 */
  parse(): JsonValue {
    this.skipWs();
    const v: JsonValue = this.parseValue();
    this.skipWs();
    if (this.i !== this.n) {
      throw new ParseError('JSON: trailing content after value');
    }
    return v;
  }

  private skipWs(): void {
    while (this.i < this.n) {
      const c: number = this.s.charCodeAt(this.i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) {
        this.i++;
      } else {
        break;
      }
    }
  }

  private parseValue(): JsonValue {
    if (this.i >= this.n) {
      throw new ParseError('JSON: unexpected end of input');
    }
    const c: string = this.s.charAt(this.i);
    if (c === '{') {
      return this.parseObject();
    }
    if (c === '[') {
      return this.parseArray();
    }
    if (c === '"') {
      return this.parseString();
    }
    if (c === 't' || c === 'f') {
      return this.parseBool();
    }
    if (c === 'n') {
      this.expect('null');
      return null;
    }
    return this.parseNumber();
  }

  private expect(word: string): void {
    if (this.s.substring(this.i, this.i + word.length) !== word) {
      throw new ParseError(`JSON: expected '${word}'`);
    }
    this.i += word.length;
  }

  private parseBool(): boolean {
    if (this.s.charAt(this.i) === 't') {
      this.expect('true');
      return true;
    }
    this.expect('false');
    return false;
  }

  private parseObject(): JsonObject {
    const obj: JsonObject = {};
    this.i++; // '{'
    this.skipWs();
    if (this.i < this.n && this.s.charAt(this.i) === '}') {
      this.i++;
      return obj;
    }
    while (true) {
      this.skipWs();
      if (this.s.charAt(this.i) !== '"') {
        throw new ParseError('JSON: expected string key');
      }
      const key: string = this.parseString();
      this.skipWs();
      if (this.s.charAt(this.i) !== ':') {
        throw new ParseError('JSON: expected ":" after key');
      }
      this.i++;
      this.skipWs();
      const val: JsonValue = this.parseValue();
      obj[key] = val;
      this.skipWs();
      const ch: string = this.s.charAt(this.i);
      if (ch === ',') {
        this.i++;
        continue;
      }
      if (ch === '}') {
        this.i++;
        break;
      }
      throw new ParseError('JSON: expected "," or "}" in object');
    }
    return obj;
  }

  private parseArray(): JsonValue[] {
    const arr: JsonValue[] = [];
    this.i++; // '['
    this.skipWs();
    if (this.i < this.n && this.s.charAt(this.i) === ']') {
      this.i++;
      return arr;
    }
    while (true) {
      this.skipWs();
      const val: JsonValue = this.parseValue();
      arr.push(val);
      this.skipWs();
      const ch: string = this.s.charAt(this.i);
      if (ch === ',') {
        this.i++;
        continue;
      }
      if (ch === ']') {
        this.i++;
        break;
      }
      throw new ParseError('JSON: expected "," or "]" in array');
    }
    return arr;
  }

  private parseString(): string {
    this.i++; // 开引号
    let out: string = '';
    while (this.i < this.n) {
      const c: string = this.s.charAt(this.i);
      this.i++;
      if (c === '"') {
        return out;
      }
      if (c === '\\') {
        if (this.i >= this.n) {
          throw new ParseError('JSON: bad escape');
        }
        const e: string = this.s.charAt(this.i);
        this.i++;
        if (e === '"') {
          out += '"';
        } else if (e === '\\') {
          out += '\\';
        } else if (e === '/') {
          out += '/';
        } else if (e === 'b') {
          out += '\b';
        } else if (e === 'f') {
          out += '\f';
        } else if (e === 'n') {
          out += '\n';
        } else if (e === 'r') {
          out += '\r';
        } else if (e === 't') {
          out += '\t';
        } else if (e === 'u') {
          const hex: string = this.s.substring(this.i, this.i + 4);
          this.i += 4;
          const code: number = parseInt(hex, 16);
          if (!Number.isFinite(code)) {
            throw new ParseError('JSON: bad \\u escape');
          }
          out += String.fromCharCode(code);
        } else {
          throw new ParseError('JSON: unknown escape');
        }
      } else {
        out += c;
      }
    }
    throw new ParseError('JSON: unterminated string');
  }

  private parseNumber(): number {
    const start: number = this.i;
    if (this.s.charAt(this.i) === '-') {
      this.i++;
    }
    while (this.i < this.n) {
      const c: string = this.s.charAt(this.i);
      if (
        (c >= '0' && c <= '9') ||
        c === '.' || c === 'e' || c === 'E' || c === '+' || c === '-'
      ) {
        this.i++;
      } else {
        break;
      }
    }
    const numStr: string = this.s.substring(start, this.i);
    const val: number = Number(numStr);
    if (!Number.isFinite(val)) {
      throw new ParseError(`JSON: invalid number '${numStr}'`);
    }
    return val;
  }
}

/** 解析 JSON 文本为 JsonValue。 */
export function parseJson(text: string): JsonValue {
  return new JsonParser(text).parse();
}
