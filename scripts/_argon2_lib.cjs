// Port of argon2.ets for self-check: BLAKE2b + Argon2id (lo/hi 32-bit limb representation).
// Faithful to RFC 9106. Used by verify-argon2.cjs against RFC test vector + plain-pass.ucxe fixture.

const BLAKE2B_IV_LO = new Uint32Array([0xf3bcc908,0x84caa73b,0xfe94f82b,0x5f1d36f1,0xade682d1,0x2b3e6c1f,0xfb41bd6b,0x137e2179]);
const BLAKE2B_IV_HI = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
const SIGMA = [
  [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],[14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3],
  [11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4],[7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8],
  [9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13],[2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9],
  [12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11],[13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10],
  [6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5],[10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0],
  [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],[14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3],
];
function rotr64Lo(lo,hi,n){if(n===32)return hi>>>0;if(n<32)return((lo>>>n)|(hi<<(32-n)))>>>0;const m=n-32;return((hi>>>m)|(lo<<(32-m)))>>>0;}
function rotr64Hi(lo,hi,n){if(n===32)return lo>>>0;if(n<32)return((hi>>>n)|(lo<<(32-n)))>>>0;const m=n-32;return((lo>>>m)|(hi<<(32-m)))>>>0;}
function add64(vLo,vHi,idx,addLo,addHi){const lo=(vLo[idx]+addLo)>>>0;const carry=(lo<(vLo[idx]>>>0))?1:0;vLo[idx]=lo;vHi[idx]=(vHi[idx]+addHi+carry)>>>0;}
function xorRotr(vLo,vHi,dst,src,n){const xl=(vLo[dst]^vLo[src])>>>0,xh=(vHi[dst]^vHi[src])>>>0;vLo[dst]=rotr64Lo(xl,xh,n);vHi[dst]=rotr64Hi(xl,xh,n);}

class Blake2b {
  constructor(outLen){
    this.outLen=outLen;this.hLo=new Uint32Array(8);this.hHi=new Uint32Array(8);
    for(let i=0;i<8;i++){this.hLo[i]=BLAKE2B_IV_LO[i];this.hHi[i]=BLAKE2B_IV_HI[i];}
    this.hLo[0]^=0x01010000^outLen;
    this.buf=new Uint8Array(128);this.bufLen=0;this.tLo=0;this.tHi=0;
  }
  update(data){let off=0;const len=data.length;while(off<len){if(this.bufLen===128){this.inc(128);this.compress(false);this.bufLen=0;}const space=128-this.bufLen;const take=Math.min(space,len-off);this.buf.set(data.subarray(off,off+take),this.bufLen);this.bufLen+=take;off+=take;}}
  digest(){this.inc(this.bufLen);for(let i=this.bufLen;i<128;i++)this.buf[i]=0;this.compress(true);const out=new Uint8Array(this.outLen);for(let i=0;i<this.outLen;i++){const w=i>>3,bw=i&7;const v=bw<4?(this.hLo[w]>>>(bw*8)):(this.hHi[w]>>>((bw-4)*8));out[i]=v&0xff;}return out;}
  inc(n){const lo=(this.tLo+n)>>>0;if(lo<this.tLo)this.tHi=(this.tHi+1)>>>0;this.tLo=lo;}
  compress(last){
    const vLo=new Uint32Array(16),vHi=new Uint32Array(16);
    for(let i=0;i<8;i++){vLo[i]=this.hLo[i];vHi[i]=this.hHi[i];vLo[i+8]=BLAKE2B_IV_LO[i];vHi[i+8]=BLAKE2B_IV_HI[i];}
    vLo[12]^=this.tLo;vHi[12]^=this.tHi;
    if(last){vLo[14]^=0xffffffff;vHi[14]^=0xffffffff;}
    const mLo=new Uint32Array(16),mHi=new Uint32Array(16);
    for(let i=0;i<16;i++){const j=i*8;mLo[i]=(this.buf[j]|(this.buf[j+1]<<8)|(this.buf[j+2]<<16)|(this.buf[j+3]<<24))>>>0;mHi[i]=(this.buf[j+4]|(this.buf[j+5]<<8)|(this.buf[j+6]<<16)|(this.buf[j+7]<<24))>>>0;}
    for(let r=0;r<12;r++){const s=SIGMA[r];
      this.mix(vLo,vHi,0,4,8,12,mLo[s[0]],mHi[s[0]],mLo[s[1]],mHi[s[1]]);
      this.mix(vLo,vHi,1,5,9,13,mLo[s[2]],mHi[s[2]],mLo[s[3]],mHi[s[3]]);
      this.mix(vLo,vHi,2,6,10,14,mLo[s[4]],mHi[s[4]],mLo[s[5]],mHi[s[5]]);
      this.mix(vLo,vHi,3,7,11,15,mLo[s[6]],mHi[s[6]],mLo[s[7]],mHi[s[7]]);
      this.mix(vLo,vHi,0,5,10,15,mLo[s[8]],mHi[s[8]],mLo[s[9]],mHi[s[9]]);
      this.mix(vLo,vHi,1,6,11,12,mLo[s[10]],mHi[s[10]],mLo[s[11]],mHi[s[11]]);
      this.mix(vLo,vHi,2,7,8,13,mLo[s[12]],mHi[s[12]],mLo[s[13]],mHi[s[13]]);
      this.mix(vLo,vHi,3,4,9,14,mLo[s[14]],mHi[s[14]],mLo[s[15]],mHi[s[15]]);
    }
    for(let i=0;i<8;i++){this.hLo[i]^=vLo[i]^vLo[i+8];this.hHi[i]^=vHi[i]^vHi[i+8];}
  }
  mix(vLo,vHi,a,b,c,d,xLo,xHi,yLo,yHi){
    add64(vLo,vHi,a,vLo[b],vHi[b]);add64(vLo,vHi,a,xLo,xHi);xorRotr(vLo,vHi,d,a,32);
    add64(vLo,vHi,c,vLo[d],vHi[d]);xorRotr(vLo,vHi,b,c,24);
    add64(vLo,vHi,a,vLo[b],vHi[b]);add64(vLo,vHi,a,yLo,yHi);xorRotr(vLo,vHi,d,a,16);
    add64(vLo,vHi,c,vLo[d],vHi[d]);xorRotr(vLo,vHi,b,c,63);
  }
}
function blake2b(input,outLen){const h=new Blake2b(outLen);h.update(input);return h.digest();}
function le32(n){const b=new Uint8Array(4);b[0]=n&0xff;b[1]=(n>>>8)&0xff;b[2]=(n>>>16)&0xff;b[3]=(n>>>24)&0xff;return b;}
function hprime(input,outLen){
  const prefix=le32(outLen);const full=new Uint8Array(prefix.length+input.length);full.set(prefix,0);full.set(input,prefix.length);
  if(outLen<=64)return blake2b(full,outLen);
  const out=new Uint8Array(outLen);let v=blake2b(full,64);out.set(v.subarray(0,32),0);let pos=32,remaining=outLen-32;
  while(remaining>64){v=blake2b(v,64);out.set(v.subarray(0,32),pos);pos+=32;remaining-=32;}
  v=blake2b(v,remaining);out.set(v.subarray(0,remaining),pos);return out;
}

const QW=128,BLK=1024,SP=4,TYPE=2;
class Block{constructor(){this.lo=new Uint32Array(QW);this.hi=new Uint32Array(QW);}
  fromBytes(b){for(let i=0;i<QW;i++){const j=i*8;this.lo[i]=(b[j]|(b[j+1]<<8)|(b[j+2]<<16)|(b[j+3]<<24))>>>0;this.hi[i]=(b[j+4]|(b[j+5]<<8)|(b[j+6]<<16)|(b[j+7]<<24))>>>0;}}
  toBytes(){const o=new Uint8Array(BLK);for(let i=0;i<QW;i++){const j=i*8;o[j]=this.lo[i]&0xff;o[j+1]=(this.lo[i]>>>8)&0xff;o[j+2]=(this.lo[i]>>>16)&0xff;o[j+3]=(this.lo[i]>>>24)&0xff;o[j+4]=this.hi[i]&0xff;o[j+5]=(this.hi[i]>>>8)&0xff;o[j+6]=(this.hi[i]>>>16)&0xff;o[j+7]=(this.hi[i]>>>24)&0xff;}return o;}
  copyFrom(s){this.lo.set(s.lo);this.hi.set(s.hi);}
  xorWith(o){for(let i=0;i<QW;i++){this.lo[i]^=o.lo[i];this.hi[i]^=o.hi[i];}}
}
function mul32to64(a,b){const aL=a&0xffff,aH=a>>>16,bL=b&0xffff,bH=b>>>16;const ll=aL*bL,lh=aL*bH,hl=aH*bL,hh=aH*bH;const cross=lh+hl;const crossLo=(cross%0x10000)*0x10000;const crossHi=Math.floor(cross/0x10000);const loFull=ll+crossLo;const carry=Math.floor(loFull/0x100000000);const lo=loFull>>>0;const hi=(hh+crossHi+carry)>>>0;return[lo,hi];}
function add64Idx(lo,hi,idx,aLo,aHi){const sum=(lo[idx]>>>0)+(aLo>>>0);const carry=Math.floor(sum/0x100000000);lo[idx]=sum>>>0;hi[idx]=(hi[idx]+aHi+carry)>>>0;}
function xorRotrIdx(lo,hi,dst,src,n){const xl=(lo[dst]^lo[src])>>>0,xh=(hi[dst]^hi[src])>>>0;lo[dst]=rotr64Lo(xl,xh,n);hi[dst]=rotr64Hi(xl,xh,n);}
function fBlaMka(lo,hi,a,b){const aLo=lo[a]>>>0,bLo=lo[b]>>>0;const prod=mul32to64(aLo,bLo);const mLo=(prod[0]<<1)>>>0;const mHi=((prod[1]<<1)|(prod[0]>>>31))>>>0;add64Idx(lo,hi,a,lo[b],hi[b]);add64Idx(lo,hi,a,mLo,mHi);}
function blamkaG(lo,hi,a,b,c,d){fBlaMka(lo,hi,a,b);xorRotrIdx(lo,hi,d,a,32);fBlaMka(lo,hi,c,d);xorRotrIdx(lo,hi,b,c,24);fBlaMka(lo,hi,a,b);xorRotrIdx(lo,hi,d,a,16);fBlaMka(lo,hi,c,d);xorRotrIdx(lo,hi,b,c,63);}
function perm(lo,hi,base){
  blamkaG(lo,hi,base+0,base+4,base+8,base+12);blamkaG(lo,hi,base+1,base+5,base+9,base+13);
  blamkaG(lo,hi,base+2,base+6,base+10,base+14);blamkaG(lo,hi,base+3,base+7,base+11,base+15);
  blamkaG(lo,hi,base+0,base+5,base+10,base+15);blamkaG(lo,hi,base+1,base+6,base+11,base+12);
  blamkaG(lo,hi,base+2,base+7,base+8,base+13);blamkaG(lo,hi,base+3,base+4,base+9,base+14);
}
function G(x,y,out,withXor,prev){
  const rLo=new Uint32Array(QW),rHi=new Uint32Array(QW);
  for(let i=0;i<QW;i++){rLo[i]=(x.lo[i]^y.lo[i])>>>0;rHi[i]=(x.hi[i]^y.hi[i])>>>0;}
  const zLo=new Uint32Array(QW),zHi=new Uint32Array(QW);zLo.set(rLo);zHi.set(rHi);
  for(let i=0;i<8;i++)perm(zLo,zHi,i*16);
  const tLo=new Uint32Array(16),tHi=new Uint32Array(16);
  for(let i=0;i<8;i++){
    for(let k=0;k<8;k++){const i0=k*16+2*i,i1=k*16+2*i+1;tLo[k*2]=zLo[i0];tHi[k*2]=zHi[i0];tLo[k*2+1]=zLo[i1];tHi[k*2+1]=zHi[i1];}
    perm(tLo,tHi,0);
    for(let k=0;k<8;k++){const i0=k*16+2*i,i1=k*16+2*i+1;zLo[i0]=tLo[k*2];zHi[i0]=tHi[k*2];zLo[i1]=tLo[k*2+1];zHi[i1]=tHi[k*2+1];}
  }
  for(let i=0;i<QW;i++){let lo=(zLo[i]^rLo[i])>>>0,hi=(zHi[i]^rHi[i])>>>0;if(withXor&&prev){lo=(lo^prev.lo[i])>>>0;hi=(hi^prev.hi[i])>>>0;}out.lo[i]=lo;out.hi[i]=hi;}
}
function clone(b){const c=new Block();c.copyFrom(b);return c;}

function argon2id(password,salt,memoryKib,timeCost,parallelism,outLen){
  const p=parallelism,tau=outLen,t=timeCost,v=0x13,y=TYPE;
  const mPrime=Math.floor(memoryKib/(SP*p))*(SP*p);
  const laneLength=Math.floor(mPrime/p);
  const segmentLength=Math.floor(laneLength/SP);
  const parts=[le32(p),le32(tau),le32(memoryKib),le32(t),le32(v),le32(y),le32(password.length),password,le32(salt.length),salt,le32(0),le32(0)];
  let total=0;for(const x of parts)total+=x.length;
  const h0i=new Uint8Array(total);let o=0;for(const x of parts){h0i.set(x,o);o+=x.length;}
  const h0=blake2b(h0i,64);
  const blocks=[];for(let i=0;i<p*laneLength;i++)blocks.push(new Block());
  const at=(lane,col)=>blocks[lane*laneLength+col];
  for(let lane=0;lane<p;lane++)for(let col=0;col<2;col++){const inp=new Uint8Array(72);inp.set(h0,0);inp.set(le32(col),64);inp.set(le32(lane),68);at(lane,col).fromBytes(hprime(inp,BLK));}
  for(let pass=0;pass<t;pass++)for(let slice=0;slice<SP;slice++)for(let lane=0;lane<p;lane++)fillSegment(blocks,at,pass,slice,lane,p,laneLength,segmentLength,t,y);
  const c=new Block();c.copyFrom(at(0,laneLength-1));for(let lane=1;lane<p;lane++)c.xorWith(at(lane,laneLength-1));
  return hprime(c.toBytes(),tau);
}
function nextAddresses(inputBlock,addressBlock,zeroBlock){
  inputBlock.lo[6]=(inputBlock.lo[6]+1)>>>0;
  if(inputBlock.lo[6]===0)inputBlock.hi[6]=(inputBlock.hi[6]+1)>>>0;
  G(zeroBlock,inputBlock,addressBlock,false,null);
  G(zeroBlock,addressBlock,addressBlock,false,null);
}
function fillSegment(blocks,at,pass,slice,lane,p,laneLength,segmentLength,t,y){
  const dataIndependent=(pass===0&&slice<SP/2);
  let addressBlock=null,inputBlock=null;
  const zeroBlock=new Block();
  if(dataIndependent){
    inputBlock=new Block();
    inputBlock.lo[0]=pass>>>0;inputBlock.lo[1]=lane>>>0;inputBlock.lo[2]=slice>>>0;
    inputBlock.lo[3]=(p*laneLength)>>>0;inputBlock.lo[4]=t>>>0;inputBlock.lo[5]=y>>>0;
    addressBlock=new Block();
  }
  const startingIndex=(pass===0&&slice===0)?2:0;
  if(dataIndependent&&pass===0&&slice===0)nextAddresses(inputBlock,addressBlock,zeroBlock);
  for(let index=startingIndex;index<segmentLength;index++){
    const col=slice*segmentLength+index;
    if(col>=laneLength)break;
    const prevCol=col===0?laneLength-1:col-1;
    const prevBlock=at(lane,prevCol);
    let j1,j2;
    if(dataIndependent){
      if(index%QW===0)nextAddresses(inputBlock,addressBlock,zeroBlock);
      const slot=index%QW;
      j1=addressBlock.lo[slot]>>>0;j2=addressBlock.hi[slot]>>>0;
    }else{j1=prevBlock.lo[0]>>>0;j2=prevBlock.hi[0]>>>0;}
    const refLane=(pass===0&&slice===0)?lane:(j2%p);
    let referenceAreaSize;
    if(pass===0){
      if(slice===0)referenceAreaSize=index-1;
      else if(refLane===lane)referenceAreaSize=slice*segmentLength+index-1;
      else referenceAreaSize=slice*segmentLength+(index===0?-1:0);
    }else{
      if(refLane===lane)referenceAreaSize=laneLength-segmentLength+index-1;
      else referenceAreaSize=laneLength-segmentLength+(index===0?-1:0);
    }
    if(referenceAreaSize<0)referenceAreaSize=0;
    let relativePosition=j1>>>0;
    relativePosition=Math.floor((relativePosition*relativePosition)/0x100000000);
    relativePosition=referenceAreaSize-1-Math.floor((referenceAreaSize*relativePosition)/0x100000000);
    let startPosition=0;
    if(pass!==0)startPosition=(slice===SP-1)?0:(slice+1)*segmentLength;
    let refIndex=(startPosition+relativePosition)%laneLength;
    if(refIndex<0)refIndex=0;
    const refBlock=at(refLane,refIndex);
    const curBlock=at(lane,col);
    const withXor=pass!==0;
    const original=withXor?clone(curBlock):null;
    G(prevBlock,refBlock,curBlock,withXor,original);
  }
}
module.exports={blake2b,argon2id,hprime};
