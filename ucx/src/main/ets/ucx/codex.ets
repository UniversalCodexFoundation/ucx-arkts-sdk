/*
 * SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * codex.ets —— metadata/codex.json 与 content/struct.json 的 JSON 映射（UCX-FORMAT §4）。
 *
 * 宽松反序列化：未知字段忽略，缺失可选字段为 undefined，不报错（SDK-API §1.2）。
 * JSON 文件中字段用 snake_case，本 SDK 对外字段用 camelCase（§2 命名映射）。
 *
 * ArkTS 注意：禁 any/unknown。JSON 取值统一为 JsonValue，访问时显式类型守卫。
 */

import {
  Codex, Structure, StructureNode, Title, Creator, Identifier,
  Series, Publisher, Description, Rights, Dates, Rating, FileVersion,
  Chapter, JsonValue, JsonObject,
} from './types';
import { ParseError } from './errors';
import { parseJson } from './json';
import { utf8Decode } from './util';

// ── JsonValue 类型守卫与安全访问 ───────────────────────────────────────────

/** 把 JsonValue 解释为对象（否则抛 ParseError）。 */
function asObject(v: JsonValue, context: string): JsonObject {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) {
    throw new ParseError(`${context}: expected JSON object`);
  }
  return v as JsonObject;
}

/** 取对象字段并解释为对象（缺失返回空对象）。 */
function objField(o: JsonObject, key: string): JsonObject | undefined {
  const v: JsonValue | undefined = o[key];
  if (v === undefined || v === null || typeof v !== 'object' || Array.isArray(v)) {
    return undefined;
  }
  return v as JsonObject;
}

/** 安全取字符串字段。 */
function str(o: JsonObject, key: string): string | undefined {
  const v: JsonValue | undefined = o[key];
  return typeof v === 'string' ? (v as string) : undefined;
}

/** 安全取数字字段。 */
function num(o: JsonObject, key: string): number | undefined {
  const v: JsonValue | undefined = o[key];
  return typeof v === 'number' ? (v as number) : undefined;
}

/** 安全取字符串数组字段。 */
function strArr(o: JsonObject, key: string): string[] | undefined {
  const v: JsonValue | undefined = o[key];
  if (!Array.isArray(v)) {
    return undefined;
  }
  const arr: JsonValue[] = v as JsonValue[];
  const out: string[] = [];
  for (let i = 0; i < arr.length; i++) {
    if (typeof arr[i] === 'string') {
      out.push(arr[i] as string);
    }
  }
  return out;
}

/** 取 map<string,string> 字段（如 identifier.custom）。 */
function strMap(o: JsonObject, key: string): Record<string, string> | undefined {
  const v: JsonValue | undefined = o[key];
  if (v === undefined || v === null || typeof v !== 'object' || Array.isArray(v)) {
    return undefined;
  }
  const obj: JsonObject = v as JsonObject;
  const out: Record<string, string> = {};
  const keys: string[] = Object.keys(obj);
  for (let i = 0; i < keys.length; i++) {
    const val: JsonValue | undefined = obj[keys[i]];
    if (typeof val === 'string') {
      out[keys[i]] = val as string;
    }
  }
  return out;
}

// ── codex.json ─────────────────────────────────────────────────────────────

/** 解析 codex.json 字节为 Codex 结构。 */
export function parseCodex(bytes: Uint8Array): Codex {
  let json: JsonValue;
  try {
    json = parseJson(utf8Decode(bytes));
  } catch (e) {
    throw new ParseError('codex.json: invalid JSON');
  }
  const o: JsonObject = asObject(json, 'codex.json');

  // identifier（必填）。
  const identObj: JsonObject = objField(o, 'identifier') ?? {};
  const ucxId: string | undefined = str(identObj, 'ucx_id');
  if (ucxId === undefined) {
    throw new ParseError('codex.json: missing identifier.ucx_id');
  }
  const identifier: Identifier = { ucxId: ucxId };
  const isbn: string | undefined = str(identObj, 'isbn');
  if (isbn !== undefined) identifier.isbn = isbn;
  const issn: string | undefined = str(identObj, 'issn');
  if (issn !== undefined) identifier.issn = issn;
  const doi: string | undefined = str(identObj, 'doi');
  if (doi !== undefined) identifier.doi = doi;
  const custom: Record<string, string> | undefined = strMap(identObj, 'custom');
  if (custom !== undefined) identifier.custom = custom;

  // title（必填）。
  const titleObj: JsonObject = objField(o, 'title') ?? {};
  const titleMain: string | undefined = str(titleObj, 'main');
  if (titleMain === undefined) {
    throw new ParseError('codex.json: missing title.main');
  }
  const title: Title = { main: titleMain };
  const subtitle: string | undefined = str(titleObj, 'subtitle');
  if (subtitle !== undefined) title.subtitle = subtitle;
  const original: string | undefined = str(titleObj, 'original');
  if (original !== undefined) title.original = original;
  const titleShort: string | undefined = str(titleObj, 'short');
  if (titleShort !== undefined) title.short = titleShort;

  // creators（必填，≥1）。
  const creatorsRaw: JsonValue | undefined = o['creators'];
  if (!Array.isArray(creatorsRaw) || (creatorsRaw as JsonValue[]).length === 0) {
    throw new ParseError('codex.json: creators must be a non-empty array');
  }
  const creatorsArr: JsonValue[] = creatorsRaw as JsonValue[];
  const creators: Creator[] = [];
  for (let i = 0; i < creatorsArr.length; i++) {
    const co: JsonObject = asObject(creatorsArr[i], `codex.json.creators[${i}]`);
    const name: string | undefined = str(co, 'name');
    const role: string | undefined = str(co, 'role');
    if (name === undefined || role === undefined) {
      throw new ParseError(`codex.json: creators[${i}] requires name and role`);
    }
    const creator: Creator = { name: name, role: role };
    const sigRef: string | undefined = str(co, 'signature_ref');
    if (sigRef !== undefined) creator.signatureRef = sigRef;
    creators.push(creator);
  }

  // language / schemaVersion（必填）。
  const language: string | undefined = str(o, 'language');
  if (language === undefined) {
    throw new ParseError('codex.json: missing language');
  }
  const schemaVersion: string | undefined = str(o, 'version');
  if (schemaVersion === undefined) {
    throw new ParseError('codex.json: missing version');
  }

  const codex: Codex = {
    ucxId: ucxId,
    title: title,
    creators: creators,
    language: language,
    identifier: identifier,
    schemaVersion: schemaVersion,
    raw: o,
  };

  // 可选嵌套对象。
  const seriesObj: JsonObject | undefined = objField(o, 'series');
  if (seriesObj !== undefined) {
    const sName: string | undefined = str(seriesObj, 'name');
    if (sName !== undefined) {
      const series: Series = { name: sName };
      const idx: number | undefined = num(seriesObj, 'index');
      if (idx !== undefined) series.index = idx;
      const total: number | undefined = num(seriesObj, 'total');
      if (total !== undefined) series.total = total;
      codex.series = series;
    }
  }

  const publisherObj: JsonObject | undefined = objField(o, 'publisher');
  if (publisherObj !== undefined) {
    const pName: string | undefined = str(publisherObj, 'name');
    if (pName !== undefined) {
      const publisher: Publisher = { name: pName };
      const imprint: string | undefined = str(publisherObj, 'imprint');
      if (imprint !== undefined) publisher.imprint = imprint;
      const sigRef: string | undefined = str(publisherObj, 'signature_ref');
      if (sigRef !== undefined) publisher.signatureRef = sigRef;
      codex.publisher = publisher;
    }
  }

  const genre: string[] | undefined = strArr(o, 'genre');
  if (genre !== undefined) codex.genre = genre;
  const tags: string[] | undefined = strArr(o, 'tags');
  if (tags !== undefined) codex.tags = tags;
  const status: string | undefined = str(o, 'status');
  if (status !== undefined) codex.status = status;
  const wordCount: number | undefined = num(o, 'word_count');
  if (wordCount !== undefined) codex.wordCount = wordCount;

  const descObj: JsonObject | undefined = objField(o, 'description');
  if (descObj !== undefined) {
    const description: Description = {};
    const dShort: string | undefined = str(descObj, 'short');
    if (dShort !== undefined) description.short = dShort;
    const dLong: string | undefined = str(descObj, 'long');
    if (dLong !== undefined) description.long = dLong;
    codex.description = description;
  }

  const rightsObj: JsonObject | undefined = objField(o, 'rights');
  if (rightsObj !== undefined) {
    const rights: Rights = {};
    const stmt: string | undefined = str(rightsObj, 'statement');
    if (stmt !== undefined) rights.statement = stmt;
    const lic: string | undefined = str(rightsObj, 'license');
    if (lic !== undefined) rights.license = lic;
    codex.rights = rights;
  }

  const datesObj: JsonObject | undefined = objField(o, 'dates');
  if (datesObj !== undefined) {
    const dates: Dates = {};
    const created: string | undefined = str(datesObj, 'created');
    if (created !== undefined) dates.created = created;
    const published: string | undefined = str(datesObj, 'published');
    if (published !== undefined) dates.published = published;
    const modified: string | undefined = str(datesObj, 'modified');
    if (modified !== undefined) dates.modified = modified;
    codex.dates = dates;
  }

  const cover: string | undefined = str(o, 'cover');
  if (cover !== undefined) codex.cover = cover;

  const ratingObj: JsonObject | undefined = objField(o, 'rating');
  if (ratingObj !== undefined) {
    const rSystem: string | undefined = str(ratingObj, 'system');
    const rValue: string | undefined = str(ratingObj, 'value');
    if (rSystem !== undefined && rValue !== undefined) {
      const rating: Rating = { system: rSystem, value: rValue };
      codex.rating = rating;
    }
  }

  const fvObj: JsonObject | undefined = objField(o, 'file_version');
  if (fvObj !== undefined) {
    const fv: FileVersion = {};
    const ver: string | undefined = str(fvObj, 'version');
    if (ver !== undefined) fv.version = ver;
    const rev: number | undefined = num(fvObj, 'revision');
    if (rev !== undefined) fv.revision = rev;
    const rel: string | undefined = str(fvObj, 'released_at');
    if (rel !== undefined) fv.releasedAt = rel;
    const cl: string | undefined = str(fvObj, 'changelog');
    if (cl !== undefined) fv.changelog = cl;
    codex.fileVersion = fv;
  }

  return codex;
}

// ── struct.json ────────────────────────────────────────────────────────────

/** 递归解析一个 StructureNode。 */
function parseNode(v: JsonValue, ctx: string): StructureNode {
  const o: JsonObject = asObject(v, ctx);
  const title: string | undefined = str(o, 'title');
  if (title === undefined) {
    throw new ParseError(`${ctx}: node missing required "title"`);
  }
  const node: StructureNode = { title: title };
  const file: string | undefined = str(o, 'file');
  if (file !== undefined) node.file = file;
  const type: string | undefined = str(o, 'type');
  if (type !== undefined) node.type = type;
  const id: string | undefined = str(o, 'id');
  if (id !== undefined) node.id = id;
  const name: string | undefined = str(o, 'name');
  if (name !== undefined) node.name = name;
  const style: string | undefined = str(o, 'style');
  if (style !== undefined) node.style = style;

  const childrenRaw: JsonValue | undefined = o['children'];
  if (Array.isArray(childrenRaw)) {
    const arr: JsonValue[] = childrenRaw as JsonValue[];
    const children: StructureNode[] = [];
    for (let i = 0; i < arr.length; i++) {
      children.push(parseNode(arr[i], `${ctx}.children[${i}]`));
    }
    node.children = children;
  }

  const enc: JsonObject | undefined = objField(o, 'encryption');
  if (enc !== undefined) {
    node.encryption = enc;
  }
  return node;
}

/** 解析 struct.json 字节为 Structure 结构。 */
export function parseStructure(bytes: Uint8Array): Structure {
  let json: JsonValue;
  try {
    json = parseJson(utf8Decode(bytes));
  } catch (e) {
    throw new ParseError('struct.json: invalid JSON');
  }
  const o: JsonObject = asObject(json, 'struct.json');

  const schemaVersion: string | undefined = str(o, 'version');
  if (schemaVersion === undefined) {
    throw new ParseError('struct.json: missing version');
  }
  const structRaw: JsonValue | undefined = o['structure'];
  if (!Array.isArray(structRaw)) {
    throw new ParseError('struct.json: missing structure array');
  }
  const arr: JsonValue[] = structRaw as JsonValue[];
  const nodes: StructureNode[] = [];
  for (let i = 0; i < arr.length; i++) {
    nodes.push(parseNode(arr[i], `struct.json.structure[${i}]`));
  }

  return { schemaVersion: schemaVersion, nodes: nodes, raw: o };
}

/** 深度优先扁平化所有叶子节点（有 file 的节点）为章节列表，按文档顺序。 */
export function flattenChapters(structure: Structure): Chapter[] {
  const out: Chapter[] = [];
  walkNodes(structure.nodes, out);
  return out;
}

/** 递归遍历节点，收集叶子。 */
function walkNodes(nodes: StructureNode[], out: Chapter[]): void {
  for (let i = 0; i < nodes.length; i++) {
    const n: StructureNode = nodes[i];
    const hasChildren: boolean = n.children !== undefined && n.children.length > 0;
    if (n.file !== undefined && !hasChildren) {
      out.push({ title: n.title, file: n.file, path: `content/${n.file}` });
    }
    if (n.children !== undefined) {
      walkNodes(n.children, out);
    }
  }
}
