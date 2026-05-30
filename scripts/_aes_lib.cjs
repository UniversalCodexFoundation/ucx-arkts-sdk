// Port of aes.ets for self-check (AES-256 + GCM decrypt + CBC decrypt).
function gmul(a, b) { let p = 0, aa = a, bb = b; for (let i = 0; i < 8; i++) { if (bb & 1) p ^= aa; const hi = aa & 0x80; aa = (aa << 1) & 0xff; if (hi) aa ^= 0x1b; bb >>= 1; } return p & 0xff; }
function buildSbox() {
  const sbox = new Uint8Array(256), log = new Uint8Array(256), alog = new Uint8Array(256);
  let x = 1; for (let i = 0; i < 255; i++) { alog[i] = x; log[x] = i; x = gmul(x, 3); }
  const inv = new Uint8Array(256); inv[0] = 0;
  for (let i = 1; i < 256; i++) inv[i] = alog[(255 - log[i]) % 255];
  for (let i = 0; i < 256; i++) { let s = inv[i], xf = s; for (let t = 0; t < 4; t++) { s = ((s << 1) | (s >> 7)) & 0xff; xf ^= s; } sbox[i] = (xf ^ 0x63) & 0xff; }
  return sbox;
}
const SBOX = buildSbox();
const INV_SBOX = (() => { const inv = new Uint8Array(256); for (let i = 0; i < 256; i++) inv[SBOX[i]] = i; return inv; })();
const RCON = new Uint8Array([0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d]);

class Aes256 {
  constructor(key) { this.rk = Aes256.expand(key); }
  static subWord(w) { return ((SBOX[(w>>>24)&255]<<24)|(SBOX[(w>>>16)&255]<<16)|(SBOX[(w>>>8)&255]<<8)|SBOX[w&255])>>>0; }
  static expand(key) {
    const nk = 8, nr = 14, tw = 4*(nr+1), w = new Uint32Array(tw);
    for (let i = 0; i < nk; i++) w[i] = ((key[4*i]<<24)|(key[4*i+1]<<16)|(key[4*i+2]<<8)|key[4*i+3])>>>0;
    for (let i = nk; i < tw; i++) {
      let t = w[i-1];
      if (i % nk === 0) { t = ((t<<8)|(t>>>24))>>>0; t = Aes256.subWord(t); t = (t ^ (RCON[i/nk-1]<<24))>>>0; }
      else if (i % nk === 4) t = Aes256.subWord(t);
      w[i] = (w[i-nk] ^ t)>>>0;
    }
    return w;
  }
  addRoundKey(s, r) { for (let c = 0; c < 4; c++) { const wk = this.rk[r*4+c]; s[c*4]^=(wk>>>24)&255; s[c*4+1]^=(wk>>>16)&255; s[c*4+2]^=(wk>>>8)&255; s[c*4+3]^=wk&255; } }
  subBytes(s){for(let i=0;i<16;i++)s[i]=SBOX[s[i]];}
  invSubBytes(s){for(let i=0;i<16;i++)s[i]=INV_SBOX[s[i]];}
  shiftRows(s){const t=new Uint8Array(16);for(let i=0;i<16;i++){const row=i%4,col=(i/4)|0,nc=(col-row+4)%4;t[nc*4+row]=s[col*4+row];}for(let i=0;i<16;i++)s[i]=t[i];}
  invShiftRows(s){const t=new Uint8Array(16);for(let i=0;i<16;i++){const row=i%4,col=(i/4)|0,nc=(col+row)%4;t[nc*4+row]=s[col*4+row];}for(let i=0;i<16;i++)s[i]=t[i];}
  mixColumns(s){for(let c=0;c<4;c++){const i=c*4,a0=s[i],a1=s[i+1],a2=s[i+2],a3=s[i+3];s[i]=gmul(a0,2)^gmul(a1,3)^a2^a3;s[i+1]=a0^gmul(a1,2)^gmul(a2,3)^a3;s[i+2]=a0^a1^gmul(a2,2)^gmul(a3,3);s[i+3]=gmul(a0,3)^a1^a2^gmul(a3,2);}}
  invMixColumns(s){for(let c=0;c<4;c++){const i=c*4,a0=s[i],a1=s[i+1],a2=s[i+2],a3=s[i+3];s[i]=gmul(a0,14)^gmul(a1,11)^gmul(a2,13)^gmul(a3,9);s[i+1]=gmul(a0,9)^gmul(a1,14)^gmul(a2,11)^gmul(a3,13);s[i+2]=gmul(a0,13)^gmul(a1,9)^gmul(a2,14)^gmul(a3,11);s[i+3]=gmul(a0,11)^gmul(a1,13)^gmul(a2,9)^gmul(a3,14);}}
  encryptBlock(input, inOff, out, outOff) {
    const s = new Uint8Array(16); for (let i = 0; i < 16; i++) s[i] = input[inOff+i];
    this.addRoundKey(s, 0);
    for (let r = 1; r < 14; r++) { this.subBytes(s); this.shiftRows(s); this.mixColumns(s); this.addRoundKey(s, r); }
    this.subBytes(s); this.shiftRows(s); this.addRoundKey(s, 14);
    for (let i = 0; i < 16; i++) out[outOff+i] = s[i];
  }
  decryptBlock(input, inOff, out, outOff) {
    const s = new Uint8Array(16); for (let i = 0; i < 16; i++) s[i] = input[inOff+i];
    this.addRoundKey(s, 14);
    for (let r = 13; r >= 1; r--) { this.invShiftRows(s); this.invSubBytes(s); this.addRoundKey(s, r); this.invMixColumns(s); }
    this.invShiftRows(s); this.invSubBytes(s); this.addRoundKey(s, 0);
    for (let i = 0; i < 16; i++) out[outOff+i] = s[i];
  }
}
function gf128Mul(x, y) {
  const z = new Uint8Array(16), v = new Uint8Array(16); v.set(y);
  for (let i = 0; i < 128; i++) {
    const bit = (x[i >> 3] >> (7 - (i & 7))) & 1;
    if (bit) for (let k = 0; k < 16; k++) z[k] ^= v[k];
    const lsb = v[15] & 1;
    for (let k = 15; k > 0; k--) v[k] = ((v[k] >>> 1) | ((v[k-1] & 1) << 7)) & 0xff;
    v[0] = (v[0] >>> 1) & 0xff; if (lsb) v[0] ^= 0xe1;
  }
  return z;
}
function ghash(h, data) {
  let y = new Uint8Array(16); const block = new Uint8Array(16);
  for (let off = 0; off < data.length; off += 16) {
    block.fill(0); const n = Math.min(16, data.length - off);
    for (let i = 0; i < n; i++) block[i] = data[off+i];
    for (let i = 0; i < 16; i++) block[i] ^= y[i];
    y = gf128Mul(block, h);
  }
  return y;
}
function incr32(c) { for (let i = 15; i >= 12; i--) { c[i] = (c[i]+1)&255; if (c[i] !== 0) return; } }
function gctr(aes, icb, input) {
  const out = new Uint8Array(input.length), counter = new Uint8Array(16); counter.set(icb);
  const ks = new Uint8Array(16);
  for (let off = 0; off < input.length; off += 16) {
    aes.encryptBlock(counter, 0, ks, 0);
    const n = Math.min(16, input.length - off);
    for (let i = 0; i < n; i++) out[off+i] = input[off+i] ^ ks[i];
    incr32(counter);
  }
  return out;
}
function writeBE64(b, off, value) { const hi = Math.floor(value/0x100000000), lo = value>>>0; b[off]=(hi>>>24)&255;b[off+1]=(hi>>>16)&255;b[off+2]=(hi>>>8)&255;b[off+3]=hi&255;b[off+4]=(lo>>>24)&255;b[off+5]=(lo>>>16)&255;b[off+6]=(lo>>>8)&255;b[off+7]=lo&255; }
function lengthBlock(aadLen, ctLen) { const b = new Uint8Array(16); writeBE64(b, 0, aadLen*8); writeBE64(b, 8, ctLen*8); return b; }
function gcmTag(aes, h, j0, aad, ct) {
  const aadPad = (16 - (aad.length % 16)) % 16, ctPad = (16 - (ct.length % 16)) % 16;
  const gi = new Uint8Array(aad.length + aadPad + ct.length + ctPad + 16); let o = 0;
  gi.set(aad, o); o += aad.length + aadPad; gi.set(ct, o); o += ct.length + ctPad; gi.set(lengthBlock(aad.length, ct.length), o);
  const s = ghash(h, gi); const ej0 = new Uint8Array(16); aes.encryptBlock(j0, 0, ej0, 0);
  const tag = new Uint8Array(16); for (let i = 0; i < 16; i++) tag[i] = ej0[i] ^ s[i]; return tag;
}
function deriveJ0(h, iv) { if (iv.length === 12) { const j0 = new Uint8Array(16); j0.set(iv, 0); j0[15] = 1; return j0; } throw new Error("only 12-byte nonce"); }
function aesGcmDecrypt(key, iv, ct, tag, aad) {
  const aes = new Aes256(key); const h = new Uint8Array(16); aes.encryptBlock(new Uint8Array(16), 0, h, 0);
  const j0 = deriveJ0(h, iv); const exp = gcmTag(aes, h, j0, aad, ct);
  let diff = 0; if (tag.length !== 16) return null; for (let i = 0; i < 16; i++) diff |= exp[i] ^ tag[i]; if (diff) return null;
  const icb = new Uint8Array(16); icb.set(j0); incr32(icb); return gctr(aes, icb, ct);
}
function aesCbcDecrypt(key, iv, ct) {
  const aes = new Aes256(key); const out = new Uint8Array(ct.length); const prev = new Uint8Array(16); prev.set(iv.subarray(0,16)); const blk = new Uint8Array(16);
  for (let off = 0; off < ct.length; off += 16) { aes.decryptBlock(ct, off, blk, 0); for (let i = 0; i < 16; i++) out[off+i] = blk[i] ^ prev[i]; for (let i = 0; i < 16; i++) prev[i] = ct[off+i]; }
  return out;
}
module.exports = { Aes256, aesGcmDecrypt, aesCbcDecrypt };
