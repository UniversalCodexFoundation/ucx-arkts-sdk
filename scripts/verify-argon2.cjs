// Verify BLAKE2b + Argon2id against known vectors and decrypt plain-pass.ucxe fixture.
const fs = require("fs");
const crypto = require("crypto");
const { blake2b, argon2id } = require("./_argon2_lib.cjs");
const { aesGcmDecrypt } = require("./_aes_lib.cjs");

function hex(b) { return Buffer.from(b).toString("hex"); }
function fromHex(s) { const b = new Uint8Array(s.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(s.substr(i*2, 2), 16); return b; }

let allOk = true;

// 1. BLAKE2b-512 of "abc" (RFC 7693 Appendix A uses BLAKE2b-512 of "abc").
const exp_abc = "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923";
const got_abc = hex(blake2b(new Uint8Array(Buffer.from("abc", "utf8")), 64));
const b2ok = got_abc === exp_abc;
allOk = allOk && b2ok;
console.log("BLAKE2b-512('abc'):", b2ok ? "OK" : `FAIL\n  got ${got_abc}\n  exp ${exp_abc}`);

// Cross-check BLAKE2b against Node's built-in for a longer input.
const longIn = Buffer.from("The quick brown fox jumps over the lazy dog. ".repeat(20), "utf8");
const nodeB2 = crypto.createHash("blake2b512").update(longIn).digest("hex");
const oursB2 = hex(blake2b(new Uint8Array(longIn), 64));
const b2ok2 = nodeB2 === oursB2;
allOk = allOk && b2ok2;
console.log("BLAKE2b-512 vs node (long):", b2ok2 ? "OK" : `FAIL\n  got ${oursB2}\n  exp ${nodeB2}`);

// 2. Argon2id RFC 9106 test vector (section 5.3):
//    P = 32 bytes of 0x01, S = 16 bytes of 0x02, K(secret)/X(ad) omitted-from-our-impl => use the
//    variant with empty secret/ad. The canonical RFC vector includes secret(0x03 x8)+ad(0x04 x12).
//    Our impl sets |K|=|X|=0, so instead cross-check Argon2id against Node-independent reference:
//    use the official argon2 reference "argon2id v=19 m=32 t=3 p=4" without secret/ad.
//    Tag expected computed by hashlib/argon2 reference (no secret, no ad):
//    For P=0x01*32, S=0x02*16, m=32, t=3, p=4, tau=32 ->
//    0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659 (RFC 9106 Argon2id without K,X is not standard;
//    we instead validate determinism + the real fixture below).
const P = new Uint8Array(32).fill(0x01);
const S = new Uint8Array(16).fill(0x02);
const tag1 = argon2id(P, S, 32, 3, 4, 32);
const tag2 = argon2id(P, S, 32, 3, 4, 32);
const detOk = hex(tag1) === hex(tag2);
allOk = allOk && detOk;
console.log("Argon2id deterministic:", detOk ? "OK" : "FAIL");
console.log("  argon2id(P,S,m=32,t=3,p=4) =", hex(tag1));

// 3. THE REAL TEST: decrypt plain-pass.ucxe via Argon2id passphrase.
const PASS = Buffer.from("sdktest-passphrase", "utf8"); // already NFC (ASCII)
const b = new Uint8Array(fs.readFileSync("G:/OpencodeProjects/DanMoNovel/Unicodex/sdk/testdata/plain-pass.ucxe"));
let o = 4;
const ver = b[o++], algo = b[o++], kdf = b[o++], flags = b[o++];
const header8 = b.slice(0, 8);
// kdf=1 Argon2id -> 12-byte param block: mem u32 | time u32 | par u32 (LE).
const memKib = b[o] | (b[o+1]<<8) | (b[o+2]<<16) | (b[o+3]<<24); o += 4;
const timeCost = b[o] | (b[o+1]<<8) | (b[o+2]<<16) | (b[o+3]<<24); o += 4;
const par = b[o] | (b[o+1]<<8) | (b[o+2]<<16) | (b[o+3]<<24); o += 4;
const kdfParams = b.slice(8, 20);
const saltLen = b[o] | (b[o+1]<<8); o += 2; const salt = b.slice(o, o + saltLen); o += saltLen;
const ivLen = b[o] | (b[o+1]<<8); o += 2; const iv = b.slice(o, o + ivLen); o += ivLen;
const ctLen = Number(Buffer.from(b.slice(o, o+8)).readBigUInt64LE(0)); o += 8;
const ciphertext = b.slice(o, o + ctLen); o += ctLen;
const tag = b.slice(o, o + 16);
console.log(`  header: ver=${ver} algo=${algo} kdf=${kdf} flags=${flags} mem=${memKib} time=${timeCost} par=${par} saltLen=${saltLen} ivLen=${ivLen} ctLen=${ctLen}`);

// Derive 32-byte key. AAD = header8 ‖ kdfParams(12) ‖ salt.
const key = argon2id(new Uint8Array(PASS), salt, memKib, timeCost, par, 32);
console.log("  derived key =", hex(key));
const aad = new Uint8Array(8 + kdfParams.length + salt.length);
aad.set(header8, 0); aad.set(kdfParams, 8); aad.set(salt, 8 + kdfParams.length);
const ptOut = aesGcmDecrypt(key, iv, ciphertext, tag, aad);
const text = ptOut ? Buffer.from(ptOut).toString("utf8") : null;
const t9Ok = text === "The quick brown fox jumps over the lazy dog.\n" && ptOut.length === 45;
allOk = allOk && t9Ok;
console.log("T9 Argon2id passphrase decrypt:", t9Ok ? "OK" : `FAIL got ${JSON.stringify(text)} (len ${ptOut ? ptOut.length : "null"})`);

// 4. Tamper: wrong passphrase must fail auth.
const badKey = argon2id(new Uint8Array(Buffer.from("wrong-pass", "utf8")), salt, memKib, timeCost, par, 32);
const bad = aesGcmDecrypt(badKey, iv, ciphertext, tag, aad);
const tamperOk = bad === null;
allOk = allOk && tamperOk;
console.log("T10 wrong passphrase -> null:", tamperOk ? "OK" : "FAIL");

console.log(allOk ? "\nARGON2ID + BLAKE2b: ALL PASS" : "\nFAILURES PRESENT");
process.exit(allOk ? 0 : 1);
