// Verify AES-256 against NIST FIPS-197 vector and AES-GCM against plain-aesgcm.ucxe fixture.
const fs = require("fs");
const { Aes256, aesGcmDecrypt } = require("./_aes_lib.cjs");

function hex(b) { return Buffer.from(b).toString("hex"); }
function fromHex(s) { const b = new Uint8Array(s.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(s.substr(i*2, 2), 16); return b; }

// FIPS-197 Appendix C.3 AES-256 known-answer.
const key = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
const pt = fromHex("00112233445566778899aabbccddeeff");
const expCt = "8ea2b7ca516745bfeafc49904b496089";
const aes = new Aes256(key);
const ct = new Uint8Array(16); aes.encryptBlock(pt, 0, ct, 0);
const encOk = hex(ct) === expCt;
console.log("AES-256 encrypt FIPS-197:", encOk ? "OK" : `FAIL got ${hex(ct)}`);
const dec = new Uint8Array(16); aes.decryptBlock(ct, 0, dec, 0);
const decOk = hex(dec) === hex(pt);
console.log("AES-256 decrypt round-trip:", decOk ? "OK" : `FAIL got ${hex(dec)}`);

// Parse plain-aesgcm.ucxe and decrypt with direct key.
const KEY = Buffer.from("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=", "base64"); // 32 bytes
const b = new Uint8Array(fs.readFileSync("G:/OpencodeProjects/DanMoNovel/Unicodex/sdk/testdata/plain-aesgcm.ucxe"));
let o = 4; const ver = b[o++], algo = b[o++], kdf = b[o++], flags = b[o++];
const header8 = b.slice(0, 8);
// kdf=0 -> no params
const saltLen = b[o] | (b[o+1] << 8); o += 2; const salt = b.slice(o, o + saltLen); o += saltLen;
const ivLen = b[o] | (b[o+1] << 8); o += 2; const iv = b.slice(o, o + ivLen); o += ivLen;
const ctLen = Number(Buffer.from(b.slice(o, o+8)).readBigUInt64LE(0)); o += 8;
const ciphertext = b.slice(o, o + ctLen); o += ctLen;
const tag = b.slice(o, o + 16);
// AAD = header8 ‖ kdfParams(0) ‖ salt(0) = header8
const aad = header8;
const ptOut = aesGcmDecrypt(KEY, iv, ciphertext, tag, aad);
const text = ptOut ? Buffer.from(ptOut).toString("utf8") : null;
const t7Ok = text === "The quick brown fox jumps over the lazy dog.\n";
console.log("T7 AES-GCM decrypt:", t7Ok ? "OK" : `FAIL got ${JSON.stringify(text)}`);

// T10: tamper last byte -> must fail auth (null).
const tamperedTag = tag.slice(); tamperedTag[tamperedTag.length - 1] ^= 0xff;
const fail = aesGcmDecrypt(KEY, iv, ciphertext, tamperedTag, aad);
console.log("T10 tamper -> null:", fail === null ? "OK" : "FAIL");
// T10b: flip flags reserved bit in AAD -> auth fail
const aad2 = header8.slice(); aad2[7] ^= 0x02;
const fail2 = aesGcmDecrypt(KEY, iv, ciphertext, tag, aad2);
console.log("T10 AAD flags tamper -> null:", fail2 === null ? "OK" : "FAIL");

const all = encOk && decOk && t7Ok && fail === null && fail2 === null;
console.log(all ? "\nAES/GCM: ALL PASS" : "\nFAILURES PRESENT");
process.exit(all ? 0 : 1);
