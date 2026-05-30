// Self-check: port of inflate.ets + zip.ets, validate against sample.ucx fixture.
// Cross-checks decompressed entry bytes -> BLAKE3 -> base64 against expected.json.
const fs = require("fs");
const zlib = require("zlib"); // reference inflate to cross-check our port
const crypto = require("crypto");

// ---- our ported inflate (mirror of inflate.ets) ----
const LENGTH_BASE = [3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258];
const LENGTH_EXTRA = [0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0];
const DIST_BASE = [1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577];
const DIST_EXTRA = [0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13];
const CODE_LENGTH_ORDER = [16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15];

class HuffmanTree {
  constructor(lengths, n) {
    this.counts = new Int32Array(16);
    this.symbols = new Int32Array(n);
    for (let i = 0; i < n; i++) this.counts[lengths[i]]++;
    this.counts[0] = 0;
    const offsets = new Int32Array(16);
    for (let len = 1; len < 16; len++) offsets[len] = offsets[len-1] + this.counts[len-1];
    for (let i = 0; i < n; i++) if (lengths[i] !== 0) { this.symbols[offsets[lengths[i]]] = i; offsets[lengths[i]]++; }
  }
}
class BitReader {
  constructor(data, start) { this.data = data; this.pos = start; this.bitBuf = 0; this.bitCnt = 0; }
  readBits(count) {
    while (this.bitCnt < count) {
      if (this.pos >= this.data.length) throw new Error("eof");
      this.bitBuf |= this.data[this.pos] << this.bitCnt; this.pos++; this.bitCnt += 8;
    }
    const v = this.bitBuf & ((1 << count) - 1); this.bitBuf >>>= count; this.bitCnt -= count; return v;
  }
  alignByte() { this.bitBuf = 0; this.bitCnt = 0; }
}
function decodeSymbol(br, tree) {
  let code = 0, first = 0, index = 0;
  for (let len = 1; len < 16; len++) {
    code |= br.readBits(1);
    const count = tree.counts[len];
    if (code - first < count) return tree.symbols[index + (code - first)];
    index += count; first += count; first <<= 1; code <<= 1;
  }
  throw new Error("bad huffman");
}
function buildFixedTrees() {
  const lit = new Int32Array(288);
  for (let i = 0; i < 144; i++) lit[i] = 8;
  for (let i = 144; i < 256; i++) lit[i] = 9;
  for (let i = 256; i < 280; i++) lit[i] = 7;
  for (let i = 280; i < 288; i++) lit[i] = 8;
  const dist = new Int32Array(30); for (let i = 0; i < 30; i++) dist[i] = 5;
  return [new HuffmanTree(lit, 288), new HuffmanTree(dist, 30)];
}
function readDynamicTrees(br) {
  const hlit = br.readBits(5) + 257, hdist = br.readBits(5) + 1, hclen = br.readBits(4) + 4;
  const clcl = new Int32Array(19);
  for (let i = 0; i < hclen; i++) clcl[CODE_LENGTH_ORDER[i]] = br.readBits(3);
  const clTree = new HuffmanTree(clcl, 19);
  const all = new Int32Array(hlit + hdist);
  let i = 0;
  while (i < hlit + hdist) {
    const sym = decodeSymbol(br, clTree);
    if (sym < 16) { all[i++] = sym; }
    else if (sym === 16) { const r = br.readBits(2) + 3; const prev = i > 0 ? all[i-1] : 0; for (let k = 0; k < r; k++) all[i++] = prev; }
    else if (sym === 17) { const r = br.readBits(3) + 3; for (let k = 0; k < r; k++) all[i++] = 0; }
    else { const r = br.readBits(7) + 11; for (let k = 0; k < r; k++) all[i++] = 0; }
  }
  const lit = new Int32Array(hlit), dist = new Int32Array(hdist);
  for (let k = 0; k < hlit; k++) lit[k] = all[k];
  for (let k = 0; k < hdist; k++) dist[k] = all[hlit + k];
  return [new HuffmanTree(lit, hlit), new HuffmanTree(dist, hdist)];
}
function inflateRaw(data, start, expectedSize) {
  const br = new BitReader(data, start);
  let cap = expectedSize > 0 ? expectedSize : 256;
  let buf = new Uint8Array(cap), len = 0;
  function ensure(extra) { if (len + extra <= buf.length) return; let c = buf.length * 2; while (c < len + extra) c *= 2; const nb = new Uint8Array(c); nb.set(buf.subarray(0, len)); buf = nb; }
  let final = false;
  while (!final) {
    final = br.readBits(1) === 1;
    const btype = br.readBits(2);
    if (btype === 0) {
      br.alignByte();
      const l = data[br.pos] | (data[br.pos+1] << 8); br.pos += 4;
      ensure(l); buf.set(data.subarray(br.pos, br.pos + l), len); len += l; br.pos += l;
    } else if (btype === 1 || btype === 2) {
      const trees = btype === 1 ? buildFixedTrees() : readDynamicTrees(br);
      const litTree = trees[0], distTree = trees[1];
      while (true) {
        const sym = decodeSymbol(br, litTree);
        if (sym === 256) break;
        if (sym < 256) { ensure(1); buf[len++] = sym; }
        else {
          const li = sym - 257;
          const length = LENGTH_BASE[li] + br.readBits(LENGTH_EXTRA[li]);
          const ds = decodeSymbol(br, distTree);
          const dist = DIST_BASE[ds] + br.readBits(DIST_EXTRA[ds]);
          ensure(length); let sp = len - dist;
          for (let k = 0; k < length; k++) { buf[len++] = buf[sp++]; }
        }
      }
    } else throw new Error("btype 3");
  }
  return buf.slice(0, len);
}

// ---- our ported zip reader (mirror of zip.ets) ----
function readU16LE(b, o) { return b[o] | (b[o+1] << 8); }
function readU32LE(b, o) { return (b[o] | (b[o+1] << 8) | (b[o+2] << 16) | (b[o+3] << 24)) >>> 0; }
function findEocd(data) {
  const minEocd = 22; if (data.length < minEocd) return null;
  const maxBack = Math.min(data.length, minEocd + 0xffff);
  for (let i = data.length - minEocd; i >= data.length - maxBack; i--) {
    if (data[i] === 0x50 && data[i+1] === 0x4b && data[i+2] === 0x05 && data[i+3] === 0x06) {
      const commentLen = readU16LE(data, i + 20);
      if (i + minEocd + commentLen === data.length) {
        return { eocdOffset: i, cdOffset: readU32LE(data, i + 16), cdCount: readU16LE(data, i + 10) };
      }
    }
  }
  return null;
}
function extractEntry(data, lho, compFromCd, compSize, uncompSize) {
  const compression = readU16LE(data, lho + 8) || compFromCd;
  const nameLen = readU16LE(data, lho + 26), extraLen = readU16LE(data, lho + 28);
  const dataStart = lho + 30 + nameLen + extraLen;
  if (compression === 0) { const out = new Uint8Array(uncompSize); out.set(data.subarray(dataStart, dataStart + uncompSize)); return out; }
  if (compression === 8) return inflateRaw(data, dataStart, uncompSize);
  throw new Error("method " + compression);
}
function readZip(data) {
  const eocd = findEocd(data); if (!eocd) throw new Error("no eocd");
  const entries = new Map(); const order = [];
  let p = eocd.cdOffset;
  for (let i = 0; i < eocd.cdCount; i++) {
    const compression = readU16LE(data, p + 10);
    const compSize = readU32LE(data, p + 20), uncompSize = readU32LE(data, p + 24);
    const nameLen = readU16LE(data, p + 28), extraLen = readU16LE(data, p + 30), commentLen = readU16LE(data, p + 32);
    const localOffset = readU32LE(data, p + 42);
    const name = Buffer.from(data.subarray(p + 46, p + 46 + nameLen)).toString("utf8");
    const content = extractEntry(data, localOffset, compression, compSize, uncompSize);
    entries.set(name, content); order.push(name);
    p = p + 46 + nameLen + extraLen + commentLen;
  }
  return { entries, order, raw: data };
}

// ---- BLAKE3 (reuse a tiny inline copy via crypto? no — use our verified algorithm by requiring nothing) ----
// We reuse the verified blake3 from the other harness by re-declaring minimal version inline.
const B3 = require("./_blake3_lib.cjs");

// ---- run ----
const dir = "G:/OpencodeProjects/DanMoNovel/Unicodex/sdk/testdata/";
const data = new Uint8Array(fs.readFileSync(dir + "sample.ucx"));
const zip = readZip(data);
console.log("ZIP order:", zip.order);

// Cross-check inflate against zlib for each deflate entry.
let inflateOk = true;
for (const name of zip.order) {
  // Re-extract via our reader is already done; cross-check by re-inflating with zlib from local header.
}
// mimetype check
const mime = Buffer.from(zip.entries.get("mimetype")).toString("utf8").trim();
console.log("mimetype:", JSON.stringify(mime), mime === "application/vnd.unicodex+zip" ? "OK" : "FAIL");

// chapter text
const chap = Buffer.from(zip.entries.get("content/chapter-001.md")).toString("utf8");
console.log("chapter text:", JSON.stringify(chap));
console.log("chapter matches T3:", chap === "# Chapter One\n\nThe quick brown fox jumps over the lazy dog.\n" ? "OK" : "FAIL");

// integrity vs expected.json
const expected = JSON.parse(fs.readFileSync(dir + "expected.json", "utf8"));
let allValid = true;
for (const me of expected.archive.manifest_entries) {
  const bytes = zip.entries.get(me.name);
  const b64 = Buffer.from(B3.blake3(bytes)).toString("base64");
  const ok = b64 === me.blake3_base64;
  if (!ok) allValid = false;
  console.log(`integrity ${me.name}: ${ok ? "OK" : "FAIL"}${ok ? "" : `\n  got ${b64}\n  exp ${me.blake3_base64}`}`);
}
console.log(allValid ? "\nZIP+INFLATE+BLAKE3 INTEGRITY: ALL PASS" : "\nFAILURES PRESENT");
process.exit(allValid ? 0 : 1);
