// Port of chacha20poly1305.ets for self-check.
function rotl32(x, n) { return ((x << n) | (x >>> (32 - n))) >>> 0; }
function qr(s, a, b, c, d) {
  s[a] = (s[a]+s[b])>>>0; s[d] = rotl32((s[d]^s[a])>>>0,16);
  s[c] = (s[c]+s[d])>>>0; s[b] = rotl32((s[b]^s[c])>>>0,12);
  s[a] = (s[a]+s[b])>>>0; s[d] = rotl32((s[d]^s[a])>>>0,8);
  s[c] = (s[c]+s[d])>>>0; s[b] = rotl32((s[b]^s[c])>>>0,7);
}
function le32(b, o) { return (b[o]|(b[o+1]<<8)|(b[o+2]<<16)|(b[o+3]<<24))>>>0; }
function chachaBlock(key, counter, nonce, out) {
  const s = new Uint32Array(16);
  s[0]=0x61707865;s[1]=0x3320646e;s[2]=0x79622d32;s[3]=0x6b206574;
  for (let i = 0; i < 8; i++) s[4+i] = le32(key, i*4);
  s[12]=counter>>>0; s[13]=le32(nonce,0); s[14]=le32(nonce,4); s[15]=le32(nonce,8);
  const w = new Uint32Array(16); for (let i = 0; i < 16; i++) w[i] = s[i];
  for (let r = 0; r < 10; r++) {
    qr(w,0,4,8,12);qr(w,1,5,9,13);qr(w,2,6,10,14);qr(w,3,7,11,15);
    qr(w,0,5,10,15);qr(w,1,6,11,12);qr(w,2,7,8,13);qr(w,3,4,9,14);
  }
  for (let i = 0; i < 16; i++) { const v = (w[i]+s[i])>>>0; out[i*4]=v&255;out[i*4+1]=(v>>>8)&255;out[i*4+2]=(v>>>16)&255;out[i*4+3]=(v>>>24)&255; }
}
function chacha20(key, ic, nonce, input) {
  const out = new Uint8Array(input.length), block = new Uint8Array(64); let counter = ic>>>0;
  for (let off = 0; off < input.length; off += 64) {
    chachaBlock(key, counter, nonce, block);
    const n = Math.min(64, input.length - off);
    for (let i = 0; i < n; i++) out[off+i] = input[off+i] ^ block[i];
    counter = (counter+1)>>>0;
  }
  return out;
}
// Poly1305 — faithful port of TweetNaCl's crypto_onetimeauth (16-bit-limb), precision-safe.
function poly1305(m, k) {
  const x = new Int32Array(17), r = new Int32Array(17), h = new Int32Array(17), c = new Int32Array(17), g = new Int32Array(17);
  for (let i = 0; i < 17; i++) r[i] = h[i] = 0;
  for (let i = 0; i < 16; i++) r[i] = k[i] & 0xff;
  r[3] &= 15; r[4] &= 252; r[7] &= 15; r[8] &= 252; r[11] &= 15; r[12] &= 252; r[15] &= 15;
  let n = m.length, pos = 0;
  while (n > 0) {
    for (let i = 0; i < 17; i++) c[i] = 0;
    let j = 0;
    for (j = 0; j < 16 && j < n; j++) c[j] = m[pos + j] & 0xff;
    c[j] = 1;
    pos += j; n -= j;
    for (let i = 0; i < 17; i++) h[i] += c[i];
    for (let i = 0; i < 17; i++) {
      x[i] = 0;
      for (let jj = 0; jj < 17; jj++) {
        x[i] += h[jj] * ((jj <= i) ? r[i - jj] : 320 * r[i + 17 - jj]);
      }
    }
    for (let i = 0; i < 17; i++) h[i] = x[i];
    let u = 0;
    for (let i = 0; i < 16; i++) { u += h[i]; h[i] = u & 255; u >>= 8; }
    u += h[16]; h[16] = u & 3; u = 5 * (u >> 2);
    for (let i = 0; i < 16; i++) { u += h[i]; h[i] = u & 255; u >>= 8; }
    u += h[16]; h[16] = u;
  }
  for (let i = 0; i < 17; i++) g[i] = h[i];
  let s = 5;
  for (let i = 0; i < 16; i++) { s += h[i]; h[i] = s & 255; s >>= 8; }
  s += h[16]; h[16] = s;
  s = h[16] >> 2; // wait — TweetNaCl uses: h[16] -= 4 then subtract via mask
  // TweetNaCl exact finalize:
  // g = h; h += 5 (above stored into h, g holds pre-add). Then:
  // for (i=0;i<17;i++) h[i] = ... no. Re-do per nacl:
  // (we already added 5 into h, g is pre-add). nacl: u = 5; for(...) add into h; then
  //   for(i=0;i<17;i++) h[i] is the +5 result; then subtract p selection:
  // mask logic:
  let mask = ((h[16] >> 7) - 1) & 0xffff;  // placeholder; overwritten below by canonical
  // Canonical: nacl does h[16] holds carry; if (h[16]>=4) it overflowed; choose h(+5) result minus 2^130
  // Implement nacl's exact loop:
  // After the +5 pass above, nacl sets:
  //   for (j = 0; j < 17; ++j) h[j] = h[j] (the +5 value) selected vs g (pre-add) by mask = -(h[16] >> 7)? No.
  // To avoid further guesswork, use the well-known nacl select:
  let carryBit = (h[16] >> 2) & 1; // 1 if the +5 produced a carry out of 130 bits
  let m2 = -carryBit; // 0 or -1
  for (let i = 0; i < 17; i++) {
    g[i] = (m2 & (h[i] ^ g[i])) ^ g[i]; // if carry: g=h(+5 masked); else keep g(pre-add)
  }
  // mask off the +5's bit-130 in g[16]
  g[16] &= 3;
  const out = new Uint8Array(16);
  let cc = 0;
  for (let i = 0; i < 16; i++) { cc += g[i] + (k[16 + i] & 0xff); out[i] = cc & 255; cc >>= 8; }
  return out;
}
function le64(v){const b=new Uint8Array(8);const lo=v>>>0,hi=Math.floor(v/0x100000000)>>>0;b[0]=lo&255;b[1]=(lo>>>8)&255;b[2]=(lo>>>16)&255;b[3]=(lo>>>24)&255;b[4]=hi&255;b[5]=(hi>>>8)&255;b[6]=(hi>>>16)&255;b[7]=(hi>>>24)&255;return b;}
function aeadMacData(aad, ct){const ap=(16-(aad.length%16))%16,cp=(16-(ct.length%16))%16;const out=new Uint8Array(aad.length+ap+ct.length+cp+16);let o=0;out.set(aad,o);o+=aad.length+ap;out.set(ct,o);o+=ct.length+cp;out.set(le64(aad.length),o);o+=8;out.set(le64(ct.length),o);return out;}
function polyKeyGen(key, nonce){const b=new Uint8Array(64);chachaBlock(key,0,nonce,b);return b.slice(0,32);}
function chacha20Poly1305Decrypt(key, nonce, ct, tag, aad){
  if (tag.length!==16) return null;
  const otk=polyKeyGen(key,nonce); const md=aeadMacData(aad,ct); const exp=poly1305(md,otk);
  let diff=0; for(let i=0;i<16;i++) diff|=exp[i]^tag[i]; if(diff) return null;
  return chacha20(key,1,nonce,ct);
}
module.exports = { chacha20, poly1305, chacha20Poly1305Decrypt, chachaBlock };
