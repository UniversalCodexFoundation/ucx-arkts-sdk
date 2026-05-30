// Port of ed25519.ets (SHA-512 hi/lo + Ed25519 via BigInt) for self-check.
const SHA512_K_HI=new Uint32Array([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,0xca273ece,0xd186b8c7,0xeada7dd6,0xf57d4f7f,0x06f067aa,0x0a637dc5,0x113f9804,0x1b710b35,0x28db77f5,0x32caab7b,0x3c9ebe0a,0x431d67c4,0x4cc5d4be,0x597f299c,0x5fcb6fab,0x6c44198c]);
const SHA512_K_LO=new Uint32Array([0xd728ae22,0x23ef65cd,0xec4d3b2f,0x8189dbbc,0xf348b538,0xb605d019,0xaf194f9b,0xda6d8118,0xa3030242,0x45706fbe,0x4ee4b28c,0xd5ffb4e2,0xf27b896f,0x3b1696b1,0x25c71235,0xcf692694,0x9ef14ad2,0x384f25e3,0x8b8cd5b5,0x77ac9c65,0x592b0275,0x6ea6e483,0xbd41fbd4,0x831153b5,0xee66dfab,0x2db43210,0x98fb213f,0xbeef0ee4,0x3da88fc2,0x930aa725,0xe003826f,0x0a0e6e70,0x46d22ffc,0x5c26c926,0x5ac42aed,0x9d95b3df,0x8baf63de,0x3c77b2a8,0x47edaee6,0x1482353b,0x4cf10364,0xbc423001,0xd0f89791,0x0654be30,0xd6ef5218,0x5565a910,0x5771202a,0x32bbd1b8,0xb8d2d0c8,0x5141ab53,0xdf8eeb99,0xe19b48a8,0xc5c95a63,0xe3418acb,0x7763e373,0xd6b2b8a3,0x5defb2fc,0x43172f60,0xa1f0ab72,0x1a6439ec,0x23631e28,0xde82bde9,0xb2c67915,0xe372532b,0xea26619c,0x21c0c207,0xcde0eb1e,0xee6ed178,0x72176fba,0xa2c898a6,0xbef90dae,0x131c471b,0x23047d84,0x40c72493,0x15c9bebc,0x9c100d4c,0xcb3e42b6,0xfc657e2a,0x3ad6faec,0x4a475817]);
const SHA512_H_HI=new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
const SHA512_H_LO=new Uint32Array([0xf3bcc908,0x84caa73b,0xfe94f82b,0x5f1d36f1,0xade682d1,0x2b3e6c1f,0xfb41bd6b,0x137e2179]);
function ror64Hi(hi,lo,n){if(n===32)return lo>>>0;if(n<32)return((hi>>>n)|(lo<<(32-n)))>>>0;const m=n-32;return((lo>>>m)|(hi<<(32-m)))>>>0;}
function ror64Lo(hi,lo,n){if(n===32)return hi>>>0;if(n<32)return((lo>>>n)|(hi<<(32-n)))>>>0;const m=n-32;return((hi>>>m)|(lo<<(32-m)))>>>0;}
function shr64Hi(hi,lo,n){if(n<32)return(hi>>>n)>>>0;return 0;}
function shr64Lo(hi,lo,n){if(n<32)return((lo>>>n)|(hi<<(32-n)))>>>0;return(hi>>>(n-32))>>>0;}
function add64(aHi,aLo,bHi,bLo){const lo=(aLo>>>0)+(bLo>>>0);const carry=Math.floor(lo/0x100000000);const hi=((aHi>>>0)+(bHi>>>0)+carry)>>>0;return[hi,lo>>>0];}
function add64x4(h0,l0,h1,l1,h2,l2,h3,l3){let lo=(l0>>>0)+(l1>>>0)+(l2>>>0)+(l3>>>0);const carry=Math.floor(lo/0x100000000);const hi=((h0>>>0)+(h1>>>0)+(h2>>>0)+(h3>>>0)+carry)>>>0;return[hi,lo>>>0];}
function add64x5(h0,l0,h1,l1,h2,l2,h3,l3,h4,l4){let lo=(l0>>>0)+(l1>>>0)+(l2>>>0)+(l3>>>0)+(l4>>>0);const carry=Math.floor(lo/0x100000000);const hi=((h0>>>0)+(h1>>>0)+(h2>>>0)+(h3>>>0)+(h4>>>0)+carry)>>>0;return[hi,lo>>>0];}
function sha512(message){
  const ml=message.length;const withOne=ml+1;const k=(112-(withOne%128)+128)%128;const totalLen=withOne+k+16;
  const buf=new Uint8Array(totalLen);buf.set(message,0);buf[ml]=0x80;
  const bitLen=ml*8;const hi=Math.floor(bitLen/0x100000000),lo=bitLen>>>0;
  buf[totalLen-8]=(hi>>>24)&255;buf[totalLen-7]=(hi>>>16)&255;buf[totalLen-6]=(hi>>>8)&255;buf[totalLen-5]=hi&255;
  buf[totalLen-4]=(lo>>>24)&255;buf[totalLen-3]=(lo>>>16)&255;buf[totalLen-2]=(lo>>>8)&255;buf[totalLen-1]=lo&255;
  const hHi=new Uint32Array(8),hLo=new Uint32Array(8);for(let i=0;i<8;i++){hHi[i]=SHA512_H_HI[i];hLo[i]=SHA512_H_LO[i];}
  const wHi=new Uint32Array(80),wLo=new Uint32Array(80);
  for(let off=0;off<totalLen;off+=128){
    for(let i=0;i<16;i++){const j=off+i*8;wHi[i]=((buf[j]<<24)|(buf[j+1]<<16)|(buf[j+2]<<8)|buf[j+3])>>>0;wLo[i]=((buf[j+4]<<24)|(buf[j+5]<<16)|(buf[j+6]<<8)|buf[j+7])>>>0;}
    for(let i=16;i<80;i++){
      const x15Hi=wHi[i-15],x15Lo=wLo[i-15];
      const s0Hi=(ror64Hi(x15Hi,x15Lo,1)^ror64Hi(x15Hi,x15Lo,8)^shr64Hi(x15Hi,x15Lo,7))>>>0;
      const s0Lo=(ror64Lo(x15Hi,x15Lo,1)^ror64Lo(x15Hi,x15Lo,8)^shr64Lo(x15Hi,x15Lo,7))>>>0;
      const x2Hi=wHi[i-2],x2Lo=wLo[i-2];
      const s1Hi=(ror64Hi(x2Hi,x2Lo,19)^ror64Hi(x2Hi,x2Lo,61)^shr64Hi(x2Hi,x2Lo,6))>>>0;
      const s1Lo=(ror64Lo(x2Hi,x2Lo,19)^ror64Lo(x2Hi,x2Lo,61)^shr64Lo(x2Hi,x2Lo,6))>>>0;
      const r=add64x4(wHi[i-16],wLo[i-16],s0Hi,s0Lo,wHi[i-7],wLo[i-7],s1Hi,s1Lo);wHi[i]=r[0];wLo[i]=r[1];
    }
    let aHi=hHi[0],aLo=hLo[0],bHi=hHi[1],bLo=hLo[1],cHi=hHi[2],cLo=hLo[2],dHi=hHi[3],dLo=hLo[3];
    let eHi=hHi[4],eLo=hLo[4],fHi=hHi[5],fLo=hLo[5],gHi=hHi[6],gLo=hLo[6],hhHi=hHi[7],hhLo=hLo[7];
    for(let i=0;i<80;i++){
      const S1Hi=(ror64Hi(eHi,eLo,14)^ror64Hi(eHi,eLo,18)^ror64Hi(eHi,eLo,41))>>>0;
      const S1Lo=(ror64Lo(eHi,eLo,14)^ror64Lo(eHi,eLo,18)^ror64Lo(eHi,eLo,41))>>>0;
      const chHi=((eHi&fHi)^(~eHi&gHi))>>>0,chLo=((eLo&fLo)^(~eLo&gLo))>>>0;
      const t1=add64x5(hhHi,hhLo,S1Hi,S1Lo,chHi,chLo,SHA512_K_HI[i],SHA512_K_LO[i],wHi[i],wLo[i]);
      const S0Hi=(ror64Hi(aHi,aLo,28)^ror64Hi(aHi,aLo,34)^ror64Hi(aHi,aLo,39))>>>0;
      const S0Lo=(ror64Lo(aHi,aLo,28)^ror64Lo(aHi,aLo,34)^ror64Lo(aHi,aLo,39))>>>0;
      const majHi=((aHi&bHi)^(aHi&cHi)^(bHi&cHi))>>>0,majLo=((aLo&bLo)^(aLo&cLo)^(bLo&cLo))>>>0;
      const t2=add64(S0Hi,S0Lo,majHi,majLo);
      hhHi=gHi;hhLo=gLo;gHi=fHi;gLo=fLo;fHi=eHi;fLo=eLo;
      const eN=add64(dHi,dLo,t1[0],t1[1]);eHi=eN[0];eLo=eN[1];
      dHi=cHi;dLo=cLo;cHi=bHi;cLo=bLo;bHi=aHi;bLo=aLo;
      const aN=add64(t1[0],t1[1],t2[0],t2[1]);aHi=aN[0];aLo=aN[1];
    }
    const u=[add64(hHi[0],hLo[0],aHi,aLo),add64(hHi[1],hLo[1],bHi,bLo),add64(hHi[2],hLo[2],cHi,cLo),add64(hHi[3],hLo[3],dHi,dLo),add64(hHi[4],hLo[4],eHi,eLo),add64(hHi[5],hLo[5],fHi,fLo),add64(hHi[6],hLo[6],gHi,gLo),add64(hHi[7],hLo[7],hhHi,hhLo)];
    for(let i=0;i<8;i++){hHi[i]=u[i][0];hLo[i]=u[i][1];}
  }
  const out=new Uint8Array(64);
  for(let i=0;i<8;i++){const vhi=hHi[i]>>>0,vlo=hLo[i]>>>0;out[i*8]=(vhi>>>24)&255;out[i*8+1]=(vhi>>>16)&255;out[i*8+2]=(vhi>>>8)&255;out[i*8+3]=vhi&255;out[i*8+4]=(vlo>>>24)&255;out[i*8+5]=(vlo>>>16)&255;out[i*8+6]=(vlo>>>8)&255;out[i*8+7]=vlo&255;}
  return out;
}

const Pp=(1n<<255n)-19n;
const L=(1n<<252n)+27742317777372353535851937790883648493n;
function mod(a){let r=a%Pp;if(r<0n)r+=Pp;return r;}
function powmod(base,exp,m){let result=1n,b=base%m,e=exp;while(e>0n){if((e&1n)===1n)result=(result*b)%m;b=(b*b)%m;e>>=1n;}return result;}
function inv(a){return powmod(mod(a),Pp-2n,Pp);}
const D=mod(-121665n*inv(121666n));
const SQRT_M1=powmod(2n,(Pp-1n)/4n,Pp);
function pointAdd(p1,p2){
  const A=mod((p1[1]-p1[0])*(p2[1]-p2[0]));const B=mod((p1[1]+p1[0])*(p2[1]+p2[0]));
  const C=mod(2n*p1[3]*p2[3]*D);const Dd=mod(2n*p1[2]*p2[2]);
  const E=mod(B-A),F=mod(Dd-C),G=mod(Dd+C),H=mod(B+A);
  return[mod(E*F),mod(G*H),mod(F*G),mod(E*H)];
}
function scalarMul(s,p){let q=[0n,1n,1n,0n],n=s,base=p;while(n>0n){if((n&1n)===1n)q=pointAdd(q,base);base=pointAdd(base,base);n>>=1n;}return q;}
function recoverX(y,sign){if(y>=Pp)return -1n;const y2=mod(y*y);const u=mod(y2-1n);const v=mod(D*y2+1n);const v3=mod(v*v*v);const v7=mod(v3*v3*v);let x=mod(u*v3*powmod(mod(u*v7),(Pp-5n)/8n,Pp));const vx2=mod(v*x*x);if(vx2===mod(-u))x=mod(x*SQRT_M1);else if(vx2!==u)return -1n;if((x&1n)!==sign)x=mod(-x);return x;}
function decodePoint(bytes){if(bytes.length!==32)return null;let y=0n;for(let i=31;i>=0;i--)y=(y<<8n)|BigInt(bytes[i]);const sign=(y>>255n)&1n;y=y&((1n<<255n)-1n);const x=recoverX(y,sign);if(x<0n)return null;return[x,y,1n,mod(x*y)];}
function encodePoint(p){const zInv=inv(p[2]);const x=mod(p[0]*zInv),y=mod(p[1]*zInv);let enc=y|((x&1n)<<255n);const out=new Uint8Array(32);for(let i=0;i<32;i++){out[i]=Number(enc&0xffn);enc>>=8n;}return out;}
function leToBig(bytes){let v=0n;for(let i=bytes.length-1;i>=0;i--)v=(v<<8n)|BigInt(bytes[i]);return v;}
function basePoint(){const by=mod(4n*inv(5n));const bx=recoverX(by,0n);return[bx,by,1n,mod(bx*by)];}
function ed25519Verify(message,signature,publicKey){
  if(signature.length!==64||publicKey.length!==32)return false;
  const rBytes=signature.subarray(0,32),sBytes=signature.subarray(32,64);
  const s=leToBig(sBytes);if(s>=L)return false;
  const A=decodePoint(publicKey);if(A===null)return false;
  const R=decodePoint(rBytes);if(R===null)return false;
  const toHash=new Uint8Array(64+message.length);toHash.set(rBytes,0);toHash.set(publicKey,32);toHash.set(message,64);
  const hk=sha512(toHash);const k=leToBig(hk)%L;
  const sB=scalarMul(s,basePoint());const kA=scalarMul(k,A);const rhs=pointAdd(R,kA);
  const lhsEnc=encodePoint(sB),rhsEnc=encodePoint(rhs);
  for(let i=0;i<32;i++)if(lhsEnc[i]!==rhsEnc[i])return false;
  return true;
}
module.exports={sha512,ed25519Verify};
