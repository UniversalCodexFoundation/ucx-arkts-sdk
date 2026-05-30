// Full signature pipeline self-check: ports signature.ets + verify.ets + der.ets logic.
// Validates Layer1 (SF/EC Ed25519) + Layer2 (signing block) against sample-signed.ucx,
// expecting status=VERIFIED, fingerprint=c7eda2f7...d0, subjectCn="UCX Sample Signer".
// Also checks sample.ucx -> UNSIGNED, and tamper rejection.
const fs = require("fs");
const zlib = require("zlib");
const { blake3 } = require("./_blake3_lib.cjs");
const { ed25519Verify } = require("./_ed25519_lib.cjs");

const DIR = "G:/OpencodeProjects/DanMoNovel/Unicodex/sdk/testdata/";
function readU16(b,o){return b[o]|(b[o+1]<<8);}
function readU32(b,o){return (b[o]|(b[o+1]<<8)|(b[o+2]<<16)|(b[o+3]<<24))>>>0;}
function readU64(b,o){return readU32(b,o)+readU32(b,o+4)*0x100000000;}
function u32le(n){return new Uint8Array([n&255,(n>>>8)&255,(n>>>16)&255,(n>>>24)&255]);}
function concat(arrs){let t=0;for(const a of arrs)t+=a.length;const o=new Uint8Array(t);let p=0;for(const a of arrs){o.set(a,p);p+=a.length;}return o;}
function toHex(b){let s="";for(const v of b)s+=(v>>4).toString(16)+(v&15).toString(16);return s;}
function bytesEqual(a,b){if(a.length!==b.length)return false;for(let i=0;i<a.length;i++)if(a[i]!==b[i])return false;return true;}

// --- minimal ZIP reader (uses zlib inflateRaw for deflate) ---
function readZip(data){
  const minE=22;let eocd=null;
  for(let i=data.length-minE;i>=Math.max(0,data.length-minE-0xffff);i--){
    if(data[i]===0x50&&data[i+1]===0x4b&&data[i+2]===0x05&&data[i+3]===0x06){const cl=readU16(data,i+20);if(i+minE+cl===data.length){eocd={eocdOffset:i,cdOffset:readU32(data,i+16),cdCount:readU16(data,i+10)};break;}}
  }
  if(!eocd)throw new Error("no eocd");
  const entries=new Map(),order=[];let p=eocd.cdOffset;
  for(let i=0;i<eocd.cdCount;i++){
    const compression=readU16(data,p+10);const compSize=readU32(data,p+20),uncompSize=readU32(data,p+24);
    const nameLen=readU16(data,p+28),extraLen=readU16(data,p+30),commentLen=readU16(data,p+32);const lho=readU32(data,p+42);
    const name=Buffer.from(data.subarray(p+46,p+46+nameLen)).toString("utf8");
    const lNameLen=readU16(data,lho+26),lExtraLen=readU16(data,lho+28);const ds=lho+30+lNameLen+lExtraLen;
    const method=readU16(data,lho+8)||compression;
    let content;
    if(method===0)content=new Uint8Array(data.subarray(ds,ds+uncompSize));
    else content=new Uint8Array(zlib.inflateRawSync(Buffer.from(data.subarray(ds,ds+compSize))));
    entries.set(name,content);order.push(name);
    p=p+46+nameLen+extraLen+commentLen;
  }
  return {entries,order,raw:data};
}

// --- DER cert parse (mirror der.ets, minimal) ---
function readTlv(data,offset){
  if(offset+2>data.length)return null;const tag=data[offset];let p=offset+1;let len=data[p];p++;
  if(len>=0x80){const nb=len&0x7f;if(nb===0||nb>4||p+nb>data.length)return null;len=0;for(let i=0;i<nb;i++){len=(len<<8)|data[p];p++;}}
  const cs=p,ce=p+len;if(ce>data.length)return null;return {tag,contentStart:cs,contentEnd:ce,tlvEnd:ce};
}
const ED_OID=new Uint8Array([0x2b,0x65,0x70]),CN_OID=new Uint8Array([0x55,0x04,0x03]);
function ceq(data,s,e,n){if(e-s!==n.length)return false;for(let i=0;i<n.length;i++)if(data[s+i]!==n[i])return false;return true;}
function findCn(data,ns,ne){let p=ns;while(p<ne){const rdn=readTlv(data,p);if(!rdn||rdn.tag!==0x31)break;let q=rdn.contentStart;while(q<rdn.contentEnd){const atv=readTlv(data,q);if(!atv||atv.tag!==0x30)break;const tt=readTlv(data,atv.contentStart);if(tt&&tt.tag===0x06&&ceq(data,tt.contentStart,tt.contentEnd,CN_OID)){const vt=readTlv(data,tt.tlvEnd);if(vt){let s="";for(let i=vt.contentStart;i<vt.contentEnd;i++)s+=String.fromCharCode(data[i]);return s;}}q=atv.tlvEnd;}p=rdn.tlvEnd;}return "";}
function parseTime(data,tag,s,e){let str="";for(let i=s;i<e;i++)str+=String.fromCharCode(data[i]);let year,rest;if(tag===0x17){const yy=parseInt(str.substring(0,2),10);year=yy<50?2000+yy:1900+yy;rest=str.substring(2);}else{year=parseInt(str.substring(0,4),10);rest=str.substring(4);}const mo=parseInt(rest.substring(0,2),10),d=parseInt(rest.substring(2,4),10),h=parseInt(rest.substring(4,6),10),mi=parseInt(rest.substring(6,8),10),se=rest.length>=10?parseInt(rest.substring(8,10),10):0;return Date.UTC(year,mo-1,d,h,mi,se);}
function parseCert(der){
  const cert=readTlv(der,0);if(!cert||cert.tag!==0x30)return null;const tbs=readTlv(der,cert.contentStart);if(!tbs||tbs.tag!==0x30)return null;
  let p=tbs.contentStart;let first=readTlv(der,p);if(!first)return null;if(first.tag===0xa0)p=first.tlvEnd;
  const serial=readTlv(der,p);if(!serial||serial.tag!==0x02)return null;p=serial.tlvEnd;
  const sigAlg=readTlv(der,p);if(!sigAlg||sigAlg.tag!==0x30)return null;p=sigAlg.tlvEnd;
  const issuer=readTlv(der,p);if(!issuer||issuer.tag!==0x30)return null;const issuerCn=findCn(der,issuer.contentStart,issuer.contentEnd);p=issuer.tlvEnd;
  const validity=readTlv(der,p);if(!validity||validity.tag!==0x30)return null;const nb=readTlv(der,validity.contentStart);const na=readTlv(der,nb.tlvEnd);
  const notBefore=parseTime(der,nb.tag,nb.contentStart,nb.contentEnd),notAfter=parseTime(der,na.tag,na.contentStart,na.contentEnd);p=validity.tlvEnd;
  const subject=readTlv(der,p);if(!subject||subject.tag!==0x30)return null;const subjectCn=findCn(der,subject.contentStart,subject.contentEnd);p=subject.tlvEnd;
  const spki=readTlv(der,p);if(!spki||spki.tag!==0x30)return null;const spkiAlg=readTlv(der,spki.contentStart);const algOid=readTlv(der,spkiAlg.contentStart);
  if(!algOid||algOid.tag!==0x06||!ceq(der,algOid.contentStart,algOid.contentEnd,ED_OID))return null;
  const bs=readTlv(der,spkiAlg.tlvEnd);if(!bs||bs.tag!==0x03)return null;const pkStart=bs.contentStart+1;if(bs.contentEnd-pkStart!==32)return null;
  const publicKey=new Uint8Array(der.subarray(pkStart,pkStart+32));
  return {publicKey,notBefore,notAfter,subjectCn,issuerCn};
}

// --- Layer 1 ---
function extractSfDigest(sfText){const lines=sfText.replace(/\r\n/g,"\n").split("\n");const pre="BLAKE3-Digest-Manifest: ";for(const l of lines)if(l.indexOf(pre)===0)return l.substring(pre.length);return null;}
function parseEc(data){if(data.length<8)return null;let o=0;const algo=readU32(data,o);o+=4;if(algo!==1)return null;const sl=readU32(data,o);o+=4;if(sl!==64||o+sl>data.length)return null;const sig=data.slice(o,o+sl);o+=sl;const cl=readU32(data,o);o+=4;if(cl<=0||o+cl>data.length)return null;return {signature:sig,certDer:data.slice(o,o+cl)};}
function verifyL1(zip,signerId,now){
  const sf=zip.entries.get(`META-INF/signatures/${signerId}.SF`);const ec=zip.entries.get(`META-INF/signatures/${signerId}.EC`);const mf=zip.entries.get("META-INF/MANIFEST.MF");
  if(!sf||!ec||!mf)return {valid:false,fingerprint:"",subjectCn:"",certType:""};
  const manifestDigest=Buffer.from(blake3(mf)).toString("base64");
  const sfDigest=extractSfDigest(Buffer.from(sf).toString("utf8"));
  const digestMatches=sfDigest!==null&&sfDigest===manifestDigest;
  const b=parseEc(ec);let sigValid=false,fp="",cn="",ct="",ctv=false,pemMatch=true;
  if(b){const cert=parseCert(b.certDer);if(cert){fp=toHex(blake3(b.certDer));cn=cert.subjectCn;ct=cert.subjectCn===cert.issuerCn?"self-signed":"ca-issued";sigValid=ed25519Verify(sf,b.signature,cert.publicKey);ctv=now>=cert.notBefore&&now<=cert.notAfter;
    const pem=zip.entries.get(`META-INF/certs/${signerId}.cert.pem`);
    if(pem){const der=pemToDer(Buffer.from(pem).toString("utf8"));pemMatch=der!==null&&bytesEqual(der,b.certDer);}}}
  return {valid:digestMatches&&sigValid&&ctv&&pemMatch,fingerprint:fp,subjectCn:cn,certType:ct,digestMatches,sigValid,ctv,pemMatch};
}
function pemToDer(pem){const b="-----BEGIN CERTIFICATE-----",e="-----END CERTIFICATE-----";const bi=pem.indexOf(b),ei=pem.indexOf(e);if(bi<0||ei<0)return null;const body=pem.substring(bi+b.length,ei).replace(/\s/g,"");return new Uint8Array(Buffer.from(body,"base64"));}

// --- Layer 2 ---
const L2_MAGIC=new Uint8Array([0x55,0x43,0x58,0x20,0x53,0x69,0x67,0x20,0x42,0x6c,0x6f,0x63,0x6b,0x20,0x31,0x00]);
function locateEocd(data){const minE=22;for(let i=data.length-minE;i>=Math.max(0,data.length-minE-0xffff);i--){if(data[i]===0x50&&data[i+1]===0x4b&&data[i+2]===0x05&&data[i+3]===0x06){const cl=readU16(data,i+20);if(i+minE+cl===data.length)return [i,readU32(data,i+16)];}}return null;}
function locateL2(data){const e=locateEocd(data);if(!e)return null;const [eocdOffset,cdOffset]=e;if(cdOffset<16||cdOffset>data.length)return null;const ms=cdOffset-16;if(!bytesEqual(data.slice(ms,cdOffset),L2_MAGIC))return null;if(ms<8)return null;const sob=readU64(data,ms-8);const blockStart=cdOffset-8-sob;if(blockStart<0||blockStart>=cdOffset)return null;if(readU64(data,blockStart)!==sob)return null;return {blockStart,cdOffset,eocdOffset,blockSize:cdOffset-blockStart};}
function parseL2Signers(block){
  if(block.length<20)return null;let o=8;const pairSize=readU64(block,o);o+=8;const pairId=readU32(block,o);o+=4;if(pairId!==0x55435801)return null;
  const sl=pairSize-4;if(sl<0||o+sl>block.length)return null;const sd=block.slice(o,o+sl);const signers=[];let p=0;
  while(p<sd.length){if(p+4>sd.length)break;const sdl=readU32(sd,p);p+=4;if(sdl<40||p+sdl>sd.length)return null;const signedData=sd.slice(p,p+sdl);
    let q=0;const dAlgo=readU32(signedData,q);q+=4;if(dAlgo!==1)return null;const digest=signedData.slice(q,q+32);q+=32;const cl=readU32(signedData,q);q+=4;if(q+cl>signedData.length)return null;const certDer=signedData.slice(q,q+cl);p+=sdl;
    if(p+8>sd.length)return null;const sAlgo=readU32(sd,p);p+=4;if(sAlgo!==1)return null;const sigLen=readU32(sd,p);p+=4;if(sigLen!==64||p+sigLen>sd.length)return null;const signature=sd.slice(p,p+sigLen);p+=sigLen;
    if(p+4>sd.length)return null;const pubLen=readU32(sd,p);p+=4;if(pubLen!==32||p+pubLen>sd.length)return null;const publicKey=sd.slice(p,p+pubLen);p+=pubLen;
    signers.push({digest,certDer,signature,publicKey,signedData});}
  return signers.length===0?null:signers;
}
function computeL2Digest(data,loc){
  const s1=data.slice(0,loc.blockStart);const ce=data.slice(loc.cdOffset,data.length);const original=concat([s1,ce]);
  const newEocd=loc.eocdOffset-loc.blockSize,newCd=loc.cdOffset-loc.blockSize;
  if(newEocd+20<=original.length){original[newEocd+16]=newCd&255;original[newEocd+17]=(newCd>>>8)&255;original[newEocd+18]=(newCd>>>16)&255;original[newEocd+19]=(newCd>>>24)&255;}
  const CS=1048576;let cc=Math.ceil(original.length/CS);if(cc===0)cc=1;const cds=[];
  for(let i=0;i<cc;i++){const start=i*CS,end=Math.min(start+CS,original.length);const chunk=original.slice(start,end);cds.push(blake3(concat([new Uint8Array([0xa5]),u32le(chunk.length),chunk])));}
  const tp=[new Uint8Array([0x5a]),u32le(cc)];for(const c of cds)tp.push(c);return blake3(concat(tp));
}
function verifyL2(data,now){
  const loc=locateL2(data);if(!loc)return null;const block=data.slice(loc.blockStart,loc.cdOffset);const signers=parseL2Signers(block);if(!signers)return [{valid:false,fingerprint:"",subjectCn:"",certType:""}];
  const dataCopy=new Uint8Array(data.length);dataCopy.set(data);const recomputed=computeL2Digest(dataCopy,loc);
  return signers.map(s=>{const dm=bytesEqual(s.digest,recomputed);const sv=ed25519Verify(s.signedData,s.signature,s.publicKey);const cert=parseCert(s.certDer);let ctv=false,cn="",ct="";if(cert){ctv=now>=cert.notBefore&&now<=cert.notAfter;cn=cert.subjectCn;ct=cert.subjectCn===cert.issuerCn?"self-signed":"ca-issued";}return {valid:dm&&sv&&ctv,fingerprint:toHex(blake3(s.certDer)),subjectCn:cn,certType:ct,dm,sv,ctv};});
}
function decideStatus(l1p,l1v,l2p,l2v){if(!l1p&&!l2p)return "UNSIGNED";if(l1p&&l2p)return (l1v&&l2v)?"VERIFIED":"INVALID";if(l1p)return l1v?"VALID_WITH_WARNINGS":"INVALID";return l2v?"VALID_WITH_WARNINGS":"INVALID";}
function verifySignatures(zip,data){
  const now=Date.now();
  const signerIds=zip.order.filter(n=>n.startsWith("META-INF/signatures/")&&n.endsWith(".SF")).map(n=>n.substring("META-INF/signatures/".length,n.length-3));
  const l1p=signerIds.length>0;const l1r=signerIds.map(id=>verifyL1(zip,id,now));let l1v=l1p;for(const r of l1r)if(!r.valid)l1v=false;
  const l2r=verifyL2(data,now);const l2p=l2r!==null;let l2v=false;if(l2r){l2v=l2r.length>0;for(const r of l2r)if(!r.valid)l2v=false;}
  const status=decideStatus(l1p,l1v,l2p,l2v);
  return {status,layer1Present:l1p,layer1Valid:l1p&&l1v,layer2Present:l2p,layer2Valid:l2p&&l2v,l1r,l2r};
}

let allOk=true;
function expect(name,cond){allOk=allOk&&cond;console.log(`${name}:`,cond?"OK":"FAIL");}

// T5: sample-signed.ucx -> VERIFIED.
const signed=new Uint8Array(fs.readFileSync(DIR+"sample-signed.ucx"));
const zipSigned=readZip(signed);
const r=verifySignatures(zipSigned,signed);
console.log("status:",r.status,"L1:",r.layer1Valid,"L2:",r.layer2Valid);
console.log("L1 detail:",JSON.stringify(r.l1r));
console.log("L2 detail:",JSON.stringify(r.l2r));
expect("T5 status VERIFIED",r.status==="VERIFIED");
expect("T5 layer1Valid && layer2Valid",r.layer1Valid&&r.layer2Valid);
expect("T5 signerId AUTHOR",zipSigned.order.some(n=>n==="META-INF/signatures/AUTHOR.SF"));
expect("T5 subjectCn",r.l1r[0].subjectCn==="UCX Sample Signer");
expect("T5 fingerprint",r.l1r[0].fingerprint==="c7eda2f7b775e395c583c220ff171a7b22c1c0ce3c887b9a3db3d74c944219d0");

// T6: sample.ucx -> UNSIGNED.
const plain=new Uint8Array(fs.readFileSync(DIR+"sample.ucx"));
const rp=verifySignatures(readZip(plain),plain);
expect("T6 status UNSIGNED",rp.status==="UNSIGNED");

// Tamper: flip a byte in a content entry's stored data -> Layer 2 digest changes -> INVALID.
const tampered=signed.slice();
// flip a byte early in the file (inside local file data region) — pick offset 200.
tampered[200]^=0xff;
const rt=verifySignatures(readZip(tampered),tampered);
expect("Tamper content -> not VERIFIED",rt.status!=="VERIFIED");

console.log(allOk?"\nSIGNATURES: ALL PASS":"\nFAILURES PRESENT");
process.exit(allOk?0:1);
