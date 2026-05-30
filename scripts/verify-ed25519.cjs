// Verify SHA-512 + Ed25519 against RFC 8032 §7.1 test vectors and Node's built-in.
const crypto = require("crypto");
const { sha512, ed25519Verify } = require("./_ed25519_lib.cjs");

function fromHex(s){const b=new Uint8Array(s.length/2);for(let i=0;i<b.length;i++)b[i]=parseInt(s.substr(i*2,2),16);return b;}
function hex(b){return Buffer.from(b).toString("hex");}
let allOk=true;

// SHA-512 KAT: empty + "abc".
const sha512Empty="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
const sha512Abc="ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
const e1=hex(sha512(new Uint8Array(0)))===sha512Empty;
const e2=hex(sha512(new Uint8Array(Buffer.from("abc"))))===sha512Abc;
allOk=allOk&&e1&&e2;
console.log("SHA-512 empty:",e1?"OK":"FAIL");
console.log("SHA-512 'abc':",e2?"OK":"FAIL");

// RFC 8032 §7.1 Test 1, 2, 3.
const vectors=[
  {pk:"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",msg:"",sig:"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"},
  {pk:"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",msg:"72",sig:"92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"},
  {pk:"fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",msg:"af82",sig:"6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"},
];
let vecOk=true;
for(let i=0;i<vectors.length;i++){
  const v=vectors[i];
  const ok=ed25519Verify(fromHex(v.msg),fromHex(v.sig),fromHex(v.pk));
  if(!ok)vecOk=false;
  console.log(`Ed25519 RFC8032 vector ${i+1}:`,ok?"OK":"FAIL");
}
allOk=allOk&&vecOk;

// Tamper: flip a signature byte -> must reject.
const v=vectors[1];
const badSig=fromHex(v.sig);badSig[0]^=0xff;
const rejected=!ed25519Verify(fromHex(v.msg),badSig,fromHex(v.pk));
allOk=allOk&&rejected;
console.log("Ed25519 tamper rejected:",rejected?"OK":"FAIL");

// Cross-check against Node crypto for a random keypair.
const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
const msg=Buffer.from("Unicodex ArkTS Ed25519 cross-check message");
const sig=crypto.sign(null,msg,privateKey);
// Extract raw 32-byte pubkey from SPKI DER (last 32 bytes).
const spki=publicKey.export({type:"spki",format:"der"});
const rawPub=new Uint8Array(spki.subarray(spki.length-32));
const crossOk=ed25519Verify(new Uint8Array(msg),new Uint8Array(sig),rawPub);
allOk=allOk&&crossOk;
console.log("Ed25519 vs node crypto:",crossOk?"OK":"FAIL");

console.log(allOk?"\nED25519 + SHA-512: ALL PASS":"\nFAILURES PRESENT");
process.exit(allOk?0:1);
