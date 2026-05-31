[English](README_en.md) | 中文

# Unicodex UCX ArkTS SDK

纯 **ArkTS** 实现的 Unicodex UCX 小说容器格式只读 SDK，面向 **HarmonyOS / OpenHarmony**。

- 解析（parse）：打开 `.ucx`、读取元数据 / 结构 / 章节、列出条目。
- 完整性校验（integrity）：BLAKE3 vs MANIFEST.MF。
- 签名验证（verify）：双层 Ed25519（Layer 1 JAR 风格 SF/EC + Layer 2 APK-v2 风格签名块）。
- 解密（decrypt）：UCXE 容器（AES-256-GCM、AES-256-CBC+HMAC-SHA256、ChaCha20-Poly1305；
  直接密钥 / 口令 KDF Argon2id、PBKDF2）。

> 本 SDK 只读，**不含写入 / 签名 / 加密**。它实现 [SDK-API.md](../SDK-API.md) 契约的能力等级 **L3**
> （parse + integrity + verify + decrypt），与字节级 [UCX-FORMAT.md](../UCX-FORMAT.md) 对齐。

## 卖点：零原生依赖的纯 ArkTS

经调研，HarmonyOS `@kit.CryptoArchitectureKit`（`@ohos.security.cryptoFramework`）：

- **不支持 Ed25519 / EdDSA**（仅 RSA / ECC(ECDSA) / SM2）——无法用于 UCX 验签；
- **不支持 BLAKE3 / BLAKE2b / Argon2id / ChaCha20-Poly1305**；
- 其 Cipher / Sign / Md API 均为**异步**（Promise / callback）。

因此本 SDK 的全部密码学原语（BLAKE3、SHA-256/512、HMAC、AES-GCM/CBC、ChaCha20-Poly1305、
Argon2id、PBKDF2、Ed25519、X.509/DER）都是**自带的同步纯 ArkTS 实现**，不依赖任何原生 crypto 库。
好处：同步接口、跨 HarmonyOS / OpenHarmony 版本一致、可在任意 ArkTS 运行时工作、人类与 LLM 可逐行审阅。

## 安装

本 SDK 以 HarmonyOS **HAR 包**形式交付（`oh-package.json5` 中 `name: "@unicodex/ucx"`，
`version: "0.4.0"`）。

通过 ohpm 引入（发布后）：

```bash
ohpm install @unicodex/ucx
```

或在工程的 `oh-package.json5` 中用本地路径依赖：

```json5
{
  "dependencies": {
    "@unicodex/ucx": "file:../path/to/sdk/arkts"
  }
}
```

## HarmonyOS 接入与用法

只从公开入口 `Index.ets` import：

```typescript
import {
  openBytes, UcxArchive, SignatureStatus, capabilities,
  decryptWithKey, decryptWithPassphrase, isUcxe,
} from '@unicodex/ucx';

// 1) 从内存字节打开（推荐；可在任意 ArkTS 运行时工作）
const data: Uint8Array = /* 读入 .ucx 字节，例如来自 @ohos.file.fs 或网络 */;
const archive: UcxArchive = openBytes(data);

// 2) 元数据与结构
console.log(archive.codex.title.main);      // 例如 "Sample Novel"
console.log(archive.codex.language);         // 例如 "en"
const chapters = archive.chapters();          // [{ title, file, path }, ...]
const files = archive.listFiles();            // 归档内全部条目名

// 3) 读章节
const text: string = archive.readChapterText('chapter-001.md');
const encrypted: boolean = archive.isChapterEncrypted('chapter-001.md');

// 4) 完整性校验（BLAKE3 vs MANIFEST）
const integrity = archive.verifyIntegrity();
console.log(integrity.valid);                 // true / false

// 5) 双层签名验证
const sig = archive.verifySignatures();
if (sig.status === SignatureStatus.VERIFIED) {
  console.log('signer:', sig.signers[0].signerId, sig.signers[0].fingerprint);
}

// 6) 解密 UCXE 字节（模块级）
//    直接密钥（32 字节，KDF=None；AES-CBC 在此模式被拒）
const key: Uint8Array = /* 32 字节密钥 */;
const plain1: Uint8Array = decryptWithKey(ucxeBytes, key);
//    口令（NFC 归一化 → KDF Argon2id/PBKDF2 → AEAD/CBC）
const plain2: Uint8Array = decryptWithPassphrase(ucxeBytes, 'sdktest-passphrase');

// 便捷：读并解密某章
const dec: Uint8Array = archive.readChapterDecryptedWithPassphrase('chapter-002.md', 'pass');
```

`open(path)`（从文件路径打开）依赖 HarmonyOS 的 `@ohos.file.fs`，是 `async`：

```typescript
import { open } from '@unicodex/ucx';
const archive = await open('/data/storage/.../sample.ucx');
```

> 在非 HarmonyOS 环境（如纯 ArkTS 测试 / Node 自检）请用 `openBytes(data)`，它纯内存、无平台依赖。

错误模型（[SDK-API §5](../SDK-API.md)）：所有错误继承 `UcxError`，可按 `category` 区分
（`InvalidFormat` / `NotFound` / `ParseError` / `Unsupported` / `DecryptionError` / `IoError`）。
**解密失败统一折叠为不透明的 `DecryptionError`**（固定文案，防 oracle）。

## 能力矩阵（capabilities）

`capabilities()` 返回：

```typescript
{
  parse: true,
  integrity: true,
  verifySignatures: true,
  decryptDirectKey: true,
  decryptPassphrase: true,
  algorithms: ['AES-256-GCM', 'AES-256-CBC', 'ChaCha20-Poly1305'],
  kdfs: ['argon2id', 'pbkdf2'],
}
```

| 能力 | 等级 | 状态 |
|------|------|------|
| 解析 open/codex/structure/chapters/readChapter/listFiles | L1 | ✅ |
| 完整性 verifyIntegrity（BLAKE3 + Base64） | L1 | ✅ |
| 验签 verifySignatures（Ed25519 双层 + X.509/DER + PEM） | L2 | ✅ |
| 解密 decryptWithKey / decryptWithPassphrase | L3 | ✅ |
| 对称算法 | — | AES-256-GCM ✅ / AES-256-CBC ✅ / ChaCha20-Poly1305 ✅ |
| KDF | — | Argon2id ✅ / PBKDF2-HMAC-SHA256 ✅ |
| 分块解密（§7.7，明文 > 64 MiB） | L3 | ✅（实现，AEAD 路径） |

本 SDK 达到 **L3**（全功能）。

## Limitations（已知限制）

- **只读**：不实现写入 / 签名 / 加密（与契约一致）。
- **`open(path)` 需要 HarmonyOS 运行时**（`@ohos.file.fs`）。在其它 ArkTS 运行时请用 `openBytes()`。
- **纯 ArkTS 密码学的性能**：Argon2id（默认 m=64 MiB、t=3、p=4）在纯 JS / ArkTS 下耗时为
  数秒量级（解密一次性调用，可接受）；大文件 BLAKE3 / AES 亦受纯实现速度限制。若平台未来提供
  同步且支持所需算法的原生 API，可作为可选加速后端接入。
- **整数范围**：内部用 JS `number`（double）表示长度 / 计数，UCX 实际值远小于 2^53，安全；
  超大（> 16 GiB 密文 / > 2^53）输入按越界拒绝。
- **X.509**：只解析 SPKI（Ed25519 OID `1.3.101.112`）、有效期、CN；**不做** CA 链 / 路径验证
  （与参考实现一致：把证书当自签名，信任内嵌公钥，信任策略交给应用）。
- **构建工具链**：DevEco Studio / ohpm 工具链在非 HarmonyOS 开发机（如 Windows CI）通常不可用，
  故未在本环境执行 HAR 构建；load-bearing 算法（BLAKE3 / BLAKE2b / SHA-256/512 / AES-GCM/CBC /
  ChaCha20-Poly1305 / Argon2id / Ed25519 / 完整 UCXE 解密管线 / 双层验签）已用 `scripts/` 下的
  Node 端口对照真实夹具与官方测试向量逐一验证（见下）。

## 一致性测试与自检验证

`scripts/` 下的 Node(`.cjs`) 端口是各 `.ets` 算法的**逐行忠实移植**，对照真实夹具与官方向量验证：

| 脚本 | 验证内容 |
|------|----------|
| `verify-blake3.cjs` | BLAKE3 官方测试向量（len 0..6144） |
| `verify-aes-gcm.cjs` | AES-256 FIPS-197 + AES-GCM 解出 `plain-aesgcm.ucxe`（T7）+ 篡改被拒（T10） |
| `verify-chacha.cjs` | ChaCha20-Poly1305 RFC 8439 + 解出 `plain-chacha.ucxe`（T8）+ 篡改被拒 |
| `verify-argon2.cjs` | BLAKE2b（RFC 7693）+ Argon2id（对照 argon2-cffi）+ Argon2id 派生密钥解出 `plain-pass.ucxe`（T9） |
| `verify-ed25519.cjs` | SHA-512 + Ed25519 RFC 8032 §7.1 向量 + 对照 Node crypto + 篡改被拒 |
| `verify-zip-integrity.cjs` | ZIP + INFLATE + BLAKE3 完整性对照 `expected.json`（T4）+ 章节文本（T3） |
| `verify-ucxe.cjs` | 完整 UCXE 解密管线：T7/T8/T9 往返 + T10 篡改（含 reserved flag bit AAD 绑定）被拒 |
| `verify-signatures.cjs` | 双层验签 `sample-signed.ucx` → status=VERIFIED、fingerprint=`c7eda2f7…d0`（T5）；`sample.ucx` → UNSIGNED（T6）；篡改被拒 |

运行：

```bash
node scripts/verify-argon2.cjs
node scripts/verify-ucxe.cjs
node scripts/verify-signatures.cjs
# ... 其余同理
```

`testdata/` 为自包含夹具副本（复制自 `sdk/testdata/`），便于独立开源与离线测试。

## 版本号说明 / Versioning（ADR-012）

本 SDK 版本号 **X.Y.Z** 的含义：

- **X.Y** = 本 SDK 所支持的 **UCX 标准版本**。前两位相同 ⇒ 对外 API 相同（同一标准线）。
- **Z** = 本 SDK 在该标准线上的**补丁号**（bug 修复 / 实现优化，不改变所支持的标准版本）。

旧标准线**持续发补丁、不废弃**（类比 Python 同时维护多条版本线）：例如 UCX 标准升级到 0.5.x 后，
仍可为支持 0.4.x 标准的 SDK 发布 `0.4.1`、`0.4.2` 等补丁。

> **当前版本 `0.4.0` 对应 UCX 标准 0.4.x。** 与父项目 `ucx 0.4.0-alpha.2` 的 wire-format 与 SDK 契约对齐。

版本格式遵循父项目约定 `x.y.z`（必要时带 `-alpha/beta/rc.N` 预发布后缀）。

## 许可

`MIT`（与父 Unicodex 项目一致，双许可可分别物化为 `LICENSE-MIT` / `LICENSE-APACHE`）。
见 [LICENSE](./LICENSE)。
