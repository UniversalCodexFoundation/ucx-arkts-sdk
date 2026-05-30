// Full UCXE decryption pipeline self-check: faithful port of ucxe.ets + kdf.ets + cbc.ets logic.
// Validates T7 (AES-GCM direct key), T8 (ChaCha20 direct key), T9 (Argon2id passphrase),
// T10 (tamper -> reject) against real fixtures. Mirrors the AAD/header/chunk logic of the .ets.
const fs = require("fs");
const { aesGcmDecrypt, aesCbcDecrypt } = require("./_aes_lib.cjs");
const { chacha20Poly1305Decrypt } = require("./_chacha_lib.cjs");
const { argon2id } = require("./_argon2_lib.cjs");
const crypto = require("crypto");

const DIR = "G:/OpencodeProjects/DanMoNovel/Unicodex/sdk/testdata";
const ALGO_GCM = 1, ALGO_CBC = 2, ALGO_CHACHA = 3;
const KDF_NONE = 0, KDF_ARGON2 = 1, KDF_PBKDF2 = 2;

function readU16(b,o){return b[o]|(b[o+1]<<8);}
function readU32(b,o){return (b[o]|(b[o+1]<<8)|(b[o+2]<<16)|(b[o+3]<<24))>>>0;}
function readU64(b,o){return readU32(b,o)+readU32(b,o+4)*0x100000000;}
function u32be(n){return new Uint8Array([(n>>>24)&255,(n>>>16)&255,(n>>>8)&255,n&255]);}
function concat(arrs){let t=0;for(const a of arrs)t+=a.length;const o=new Uint8Array(t);let p=0;for(const a of arrs){o.set(a,p);p+=a.length;}return o;}

function tagLen(algo){return algo===ALGO_GCM?16:algo===ALGO_CHACHA?16:algo===ALGO_CBC?32:-1;}

function parseUcxe(data){
  if(data.length<8)return null;
  if(!(data[0]===0x55&&data[1]===0x43&&data[2]===0x58&&data[3]===0x45))return null;
  if(data[4]!==1)return null;
  const algorithm=data[5],kdfId=data[6],flags=data[7];
  const tl=tagLen(algorithm);if(tl<0)return null;
  const header8=data.slice(0,8);const chunked=(flags&1)!==0;
  let o=8,memoryKib=0,timeCost=0,parallelism=0,iterations=0,kdfRaw;
  if(kdfId===KDF_NONE)kdfRaw=new Uint8Array(0);
  else if(kdfId===KDF_ARGON2){if(o+12>data.length)return null;memoryKib=readU32(data,o);timeCost=readU32(data,o+4);parallelism=readU32(data,o+8);kdfRaw=data.slice(o,o+12);o+=12;}
  else if(kdfId===KDF_PBKDF2){if(o+4>data.length)return null;iterations=readU32(data,o);kdfRaw=data.slice(o,o+4);o+=4;}
  else return null;
  if(o+2>data.length)return null;const saltLen=readU16(data,o);o+=2;if(saltLen>1024||o+saltLen>data.length)return null;const salt=data.slice(o,o+saltLen);o+=saltLen;
  if(o+2>data.length)return null;const ivLen=readU16(data,o);o+=2;if(ivLen>256||o+ivLen>data.length)return null;const iv=data.slice(o,o+ivLen);o+=ivLen;
  if(o+8>data.length)return null;const ctLen=readU64(data,o);o+=8;if(o+ctLen>data.length)return null;const ciphertext=data.slice(o,o+ctLen);o+=ctLen;
  if(o+tl>data.length)return null;const tag=data.slice(o,o+tl);
  return {header8,algorithm,kdfId,flags,chunked,memoryKib,timeCost,parallelism,iterations,kdfRaw,salt,iv,ciphertext,tag};
}
function aeadAad(h){return concat([h.header8,h.kdfRaw,h.salt]);}
function aeadOne(algo,key,nonce,ct,tag,aad){
  if(algo===ALGO_GCM)return aesGcmDecrypt(key,nonce,ct,tag,aad);
  if(algo===ALGO_CHACHA)return chacha20Poly1305Decrypt(key,nonce,ct,tag,aad);
  return null;
}
function decryptChunked(h,key,aad){
  if(h.iv.length!==12)return null;const s=h.ciphertext;if(s.length<4)return null;
  let o=0;const cc=readU32(s,o);o+=4;if(cc>s.length)return null;const parts=[];
  for(let i=0;i<cc;i++){if(o+4>s.length)return null;const sz=readU32(s,o);o+=4;if(o+sz+16>s.length)return null;const ct=s.slice(o,o+sz);o+=sz;const tag=s.slice(o,o+16);o+=16;const nonce=new Uint8Array(12);nonce.set(h.iv.subarray(0,8),0);nonce.set(u32be(i),8);const pt=aeadOne(h.algorithm,key,nonce,ct,tag,aad);if(pt===null)return null;parts.push(pt);}
  if(o!==s.length)return null;return concat(parts);
}
function decryptAead(h,key){const aad=aeadAad(h);if(h.chunked)return decryptChunked(h,key,aad);if(h.iv.length!==12||h.tag.length!==16)return null;return aeadOne(h.algorithm,key,h.iv,h.ciphertext,h.tag,aad);}
function decryptWithKey(data,key){const h=parseUcxe(data);if(!h)return null;if(h.kdfId!==KDF_NONE)return null;if(key.length!==32)return null;if(h.algorithm===ALGO_CBC)return null;return decryptAead(h,key);}

function pkcs7Unpad(d){const len=d.length;if(len===0||len%16!==0)return null;const pad=d[len-1];if(pad<1||pad>16||pad>len)return null;for(let i=len-pad;i<len;i++)if(d[i]!==pad)return null;return d.slice(0,len-pad);}
function cbcHmacDecrypt(encKey,macKey,iv,ct,tag,headerAad){
  if(iv.length!==16||tag.length!==32)return null;if(ct.length===0||ct.length%16!==0)return null;
  const macData=concat([headerAad,iv,ct]);const exp=new Uint8Array(crypto.createHmac("sha256",Buffer.from(macKey)).update(Buffer.from(macData)).digest());
  if(exp.length!==tag.length)return null;let diff=0;for(let i=0;i<exp.length;i++)diff|=exp[i]^tag[i];if(diff!==0)return null;
  let padded;try{padded=aesCbcDecrypt(encKey,iv,ct);}catch(e){return null;}return pkcs7Unpad(padded);
}
function deriveKey(h,passphrase,dkLen){
  const pw=new Uint8Array(Buffer.from(passphrase.normalize("NFC"),"utf8"));
  if(h.salt.length!==16||pw.length===0)return null;
  if(h.kdfId===KDF_ARGON2)return argon2id(pw,h.salt,h.memoryKib,h.timeCost,h.parallelism,dkLen);
  if(h.kdfId===KDF_PBKDF2){const o=new Uint8Array(crypto.pbkdf2Sync(Buffer.from(pw),Buffer.from(h.salt),h.iterations,dkLen,"sha256"));return o;}
  return null;
}
function decryptWithPassphrase(data,passphrase){
  const h=parseUcxe(data);if(!h)return null;if(h.kdfId===KDF_NONE)return null;
  const isCbc=h.algorithm===ALGO_CBC;const dkLen=isCbc?64:32;const d=deriveKey(h,passphrase,dkLen);if(d===null)return null;
  if(isCbc)return cbcHmacDecrypt(d.slice(0,32),d.slice(32,64),h.iv,h.ciphertext,h.tag,h.header8);
  return decryptAead(h,d);
}

const PLAIN="The quick brown fox jumps over the lazy dog.\n";
const KEY=new Uint8Array(Buffer.from("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=","base64"));
let allOk=true;
function check(name,got){const ok=got===PLAIN;allOk=allOk&&ok;console.log(`${name}:`,ok?"OK":`FAIL got ${JSON.stringify(got)}`);}

// T7 AES-GCM direct key.
const aesgcm=new Uint8Array(fs.readFileSync(`${DIR}/plain-aesgcm.ucxe`));
const t7=decryptWithKey(aesgcm,KEY);check("T7 decryptWithKey(plain-aesgcm)",t7?Buffer.from(t7).toString("utf8"):null);
// T8 ChaCha20 direct key.
const chacha=new Uint8Array(fs.readFileSync(`${DIR}/plain-chacha.ucxe`));
const t8=decryptWithKey(chacha,KEY);check("T8 decryptWithKey(plain-chacha)",t8?Buffer.from(t8).toString("utf8"):null);
// T9 Argon2id passphrase.
const pass=new Uint8Array(fs.readFileSync(`${DIR}/plain-pass.ucxe`));
const t9=decryptWithPassphrase(pass,"sdktest-passphrase");check("T9 decryptWithPassphrase(plain-pass)",t9?Buffer.from(t9).toString("utf8"):null);

// T10 tamper: flip a ciphertext byte in each fixture -> must return null.
function tamperCt(data){const b=data.slice();/* find ct region by re-parse offsets */const h=parseUcxe(data);
  // locate ct start: header(8)+kdfRaw+2+salt+2+iv+8
  let o=8+h.kdfRaw.length+2+h.salt.length+2+h.iv.length+8; b[o]^=0xff; return b;}
function tamperHeaderFlags(data){const b=data.slice();b[7]^=0x02;/* reserved bit -> AAD changes */return b;}
const tk7=decryptWithKey(tamperCt(aesgcm),KEY);
const tk8=decryptWithKey(tamperCt(chacha),KEY);
const tk9=decryptWithPassphrase(tamperCt(pass),"sdktest-passphrase");
const tf7=decryptWithKey(tamperHeaderFlags(aesgcm),KEY);
const t10ok=tk7===null&&tk8===null&&tk9===null&&tf7===null;
allOk=allOk&&t10ok;
console.log("T10 tamper rejected (gcm/chacha/pass ct + flags AAD):",t10ok?"OK":`FAIL ${tk7},${tk8},${tk9},${tf7}`);

// Negative: wrong passphrase, wrong key.
const wk=decryptWithKey(aesgcm,new Uint8Array(32));
const wp=decryptWithPassphrase(pass,"nope");
const negOk=wk===null&&wp===null;allOk=allOk&&negOk;
console.log("Negative (wrong key/pass) -> null:",negOk?"OK":"FAIL");

console.log(allOk?"\nUCXE PIPELINE: ALL PASS":"\nFAILURES PRESENT");
process.exit(allOk?0:1);
