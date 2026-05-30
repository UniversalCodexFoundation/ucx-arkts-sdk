// Verify ChaCha20-Poly1305 against RFC 8439 §2.8.2 AEAD vector + plain-chacha.ucxe fixture (T8).
const fs = require("fs");
const { chacha20Poly1305Decrypt, poly1305 } = require("./_chacha_lib.cjs");
function fromHex(s){s=s.replace(/[^0-9a-f]/gi,"");const b=new Uint8Array(s.length/2);for(let i=0;i<b.length;i++)b[i]=parseInt(s.substr(i*2,2),16);return b;}
function hex(b){return Buffer.from(b).toString("hex");}

// RFC 8439 §2.5.2 Poly1305 KAT.
{
  const key = fromHex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
  const msg = Buffer.from("Cryptographic Forum Research Group");
  const tag = poly1305(new Uint8Array(msg), key);
  const exp = "a8061dc1305136c6c22b8baf0c0127a9";
  console.log("Poly1305 KAT:", hex(tag) === exp ? "OK" : `FAIL got ${hex(tag)}`);
}

// RFC 8439 §2.8.2 AEAD decrypt KAT.
{
  const key = fromHex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
  const nonce = fromHex("070000004041424344454647");
  const aad = fromHex("50515253c0c1c2c3c4c5c6c7");
  const ct = fromHex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116");
  const tag = fromHex("1ae10b594f09e26a7e902ecbd0600691");
  const pt = chacha20Poly1305Decrypt(key, nonce, ct, tag, aad);
  const exp = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
  const got = pt ? Buffer.from(pt).toString("utf8") : null;
  console.log("AEAD decrypt KAT:", got === exp ? "OK" : `FAIL got ${JSON.stringify(got)}`);
}

// T8: plain-chacha.ucxe direct-key.
{
  const KEY = Buffer.from("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=", "base64");
  const b = new Uint8Array(fs.readFileSync("G:/OpencodeProjects/DanMoNovel/Unicodex/sdk/testdata/plain-chacha.ucxe"));
  const header8 = b.slice(0, 8); let o = 8;
  const saltLen = b[o]|(b[o+1]<<8); o += 2; o += saltLen;
  const ivLen = b[o]|(b[o+1]<<8); o += 2; const iv = b.slice(o, o+ivLen); o += ivLen;
  const ctLen = Number(Buffer.from(b.slice(o,o+8)).readBigUInt64LE(0)); o += 8;
  const ct = b.slice(o, o+ctLen); o += ctLen; const tag = b.slice(o, o+16);
  const aad = header8; // kdf=0, no salt
  const pt = chacha20Poly1305Decrypt(KEY, iv, ct, tag, aad);
  const got = pt ? Buffer.from(pt).toString("utf8") : null;
  const ok = got === "The quick brown fox jumps over the lazy dog.\n";
  console.log("T8 ChaCha20-Poly1305 decrypt:", ok ? "OK" : `FAIL got ${JSON.stringify(got)}`);
  // tamper
  const tt = tag.slice(); tt[15] ^= 0xff;
  console.log("T8 tamper -> null:", chacha20Poly1305Decrypt(KEY, iv, ct, tt, aad) === null ? "OK" : "FAIL");
}
