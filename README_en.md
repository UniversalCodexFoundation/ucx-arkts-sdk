English | [中文](README.md)

# Unicodex UCX ArkTS SDK

A read-only SDK for the Unicodex UCX novel container format, implemented purely in **ArkTS**, targeting **HarmonyOS / OpenHarmony**.

- Parse: open `.ucx` files, read metadata / structure / chapters, list entries.
- Integrity: BLAKE3 vs MANIFEST.MF.
- Signature verification: dual-layer Ed25519 (Layer 1 JAR-style SF/EC + Layer 2 APK-v2-style signature block).
- Decryption: UCXE containers (AES-256-GCM, AES-256-CBC+HMAC-SHA256, ChaCha20-Poly1305;
  direct key / passphrase KDF Argon2id, PBKDF2).

> This SDK is read-only and **does not include write / sign / encrypt** functionality. It implements capability level **L3**
> (parse + integrity + verify + decrypt) of the [SDK-API.md](../SDK-API.md) contract, aligned with the byte-level [UCX-FORMAT.md](../UCX-FORMAT.md).

## Highlight: Zero Native Dependencies, Pure ArkTS

After investigation, HarmonyOS `@kit.CryptoArchitectureKit` (`@ohos.security.cryptoFramework`):

- **Does not support Ed25519 / EdDSA** (only RSA / ECC(ECDSA) / SM2) -- cannot be used for UCX signature verification;
- **Does not support BLAKE3 / BLAKE2b / Argon2id / ChaCha20-Poly1305**;
- Its Cipher / Sign / Md APIs are all **asynchronous** (Promise / callback).

Therefore, all cryptographic primitives in this SDK (BLAKE3, SHA-256/512, HMAC, AES-GCM/CBC, ChaCha20-Poly1305,
Argon2id, PBKDF2, Ed25519, X.509/DER) are **bundled synchronous pure ArkTS implementations**, with no dependency on any native crypto library.
Benefits: synchronous interfaces, consistent behavior across HarmonyOS / OpenHarmony versions, works in any ArkTS runtime, line-by-line auditable by humans and LLMs.

## Installation

This SDK is delivered as a HarmonyOS **HAR package** (`oh-package.json5`: `name: "@unicodex/ucx"`,
`version: "0.4.0"`).

Install via ohpm (after publication):

```bash
ohpm install @unicodex/ucx
```

Or add a local path dependency in your project's `oh-package.json5`:

```json5
{
  "dependencies": {
    "@unicodex/ucx": "file:../path/to/sdk/arkts"
  }
}
```

## HarmonyOS Integration and Usage

Import only from the public entry point `Index.ets`:

```typescript
import {
  openBytes, UcxArchive, SignatureStatus, capabilities,
  decryptWithKey, decryptWithPassphrase, isUcxe,
} from '@unicodex/ucx';

// 1) Open from in-memory bytes (recommended; works in any ArkTS runtime)
const data: Uint8Array = /* read .ucx bytes, e.g. from @ohos.file.fs or network */;
const archive: UcxArchive = openBytes(data);

// 2) Metadata and structure
console.log(archive.codex.title.main);      // e.g. "Sample Novel"
console.log(archive.codex.language);         // e.g. "en"
const chapters = archive.chapters();          // [{ title, file, path }, ...]
const files = archive.listFiles();            // all entry names in the archive

// 3) Read chapters
const text: string = archive.readChapterText('chapter-001.md');
const encrypted: boolean = archive.isChapterEncrypted('chapter-001.md');

// 4) Integrity check (BLAKE3 vs MANIFEST)
const integrity = archive.verifyIntegrity();
console.log(integrity.valid);                 // true / false

// 5) Dual-layer signature verification
const sig = archive.verifySignatures();
if (sig.status === SignatureStatus.VERIFIED) {
  console.log('signer:', sig.signers[0].signerId, sig.signers[0].fingerprint);
}

// 6) Decrypt UCXE bytes (module-level)
//    Direct key (32 bytes, KDF=None; AES-CBC is rejected in this mode)
const key: Uint8Array = /* 32-byte key */;
const plain1: Uint8Array = decryptWithKey(ucxeBytes, key);
//    Passphrase (NFC normalization -> KDF Argon2id/PBKDF2 -> AEAD/CBC)
const plain2: Uint8Array = decryptWithPassphrase(ucxeBytes, 'sdktest-passphrase');

// Convenience: read and decrypt a chapter
const dec: Uint8Array = archive.readChapterDecryptedWithPassphrase('chapter-002.md', 'pass');
```

`open(path)` (open from file path) depends on HarmonyOS `@ohos.file.fs` and is `async`:

```typescript
import { open } from '@unicodex/ucx';
const archive = await open('/data/storage/.../sample.ucx');
```

> In non-HarmonyOS environments (e.g. pure ArkTS tests / Node self-checks), use `openBytes(data)` -- it is purely in-memory with no platform dependencies.

Error model ([SDK-API section 5](../SDK-API.md)): all errors inherit from `UcxError` and can be distinguished by `category`
(`InvalidFormat` / `NotFound` / `ParseError` / `Unsupported` / `DecryptionError` / `IoError`).
**Decryption failures are uniformly folded into an opaque `DecryptionError`** (fixed message, to prevent oracle attacks).

## Capability Matrix (capabilities)

`capabilities()` returns:

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

| Capability | Level | Status |
|------|------|------|
| Parse: open/codex/structure/chapters/readChapter/listFiles | L1 | Done |
| Integrity: verifyIntegrity (BLAKE3 + Base64) | L1 | Done |
| Signature verification: verifySignatures (Ed25519 dual-layer + X.509/DER + PEM) | L2 | Done |
| Decryption: decryptWithKey / decryptWithPassphrase | L3 | Done |
| Symmetric algorithms | -- | AES-256-GCM (Done) / AES-256-CBC (Done) / ChaCha20-Poly1305 (Done) |
| KDF | -- | Argon2id (Done) / PBKDF2-HMAC-SHA256 (Done) |
| Chunked decryption (section 7.7, plaintext > 64 MiB) | L3 | Done (implemented, AEAD path) |

This SDK achieves **L3** (full functionality).

## Limitations

- **Read-only**: does not implement write / sign / encrypt (consistent with the contract).
- **`open(path)` requires the HarmonyOS runtime** (`@ohos.file.fs`). In other ArkTS runtimes, use `openBytes()`.
- **Performance of pure ArkTS cryptography**: Argon2id (default m=64 MiB, t=3, p=4) takes several seconds
  in pure JS / ArkTS (acceptable for one-time decryption calls); large-file BLAKE3 / AES is also limited
  by the pure implementation's speed. If the platform provides a synchronous native API supporting the
  required algorithms in the future, it can be integrated as an optional acceleration backend.
- **Integer range**: internally uses JS `number` (double) for lengths / counts; actual UCX values are far
  below 2^53, so this is safe; excessively large inputs (> 16 GiB ciphertext / > 2^53) are rejected as out-of-bounds.
- **X.509**: only parses SPKI (Ed25519 OID `1.3.101.112`), validity period, and CN; **does not** perform
  CA chain / path validation (consistent with the reference implementation: treats certificates as self-signed,
  trusts the embedded public key, delegates trust policy to the application).
- **Build toolchain**: DevEco Studio / ohpm toolchain is typically unavailable on non-HarmonyOS development
  machines (e.g. Windows CI), so HAR builds have not been executed in this environment; load-bearing algorithms
  (BLAKE3 / BLAKE2b / SHA-256/512 / AES-GCM/CBC / ChaCha20-Poly1305 / Argon2id / Ed25519 / full UCXE
  decryption pipeline / dual-layer signature verification) have been verified one by one against real fixtures
  and official test vectors using Node ports under `scripts/` (see below).

## Conformance Tests and Self-Verification

The Node (`.cjs`) ports under `scripts/` are **line-by-line faithful translations** of each `.ets` algorithm, verified against real fixtures and official vectors:

| Script | Verified Content |
|------|----------|
| `verify-blake3.cjs` | BLAKE3 official test vectors (len 0..6144) |
| `verify-aes-gcm.cjs` | AES-256 FIPS-197 + AES-GCM decryption of `plain-aesgcm.ucxe` (T7) + tamper rejected (T10) |
| `verify-chacha.cjs` | ChaCha20-Poly1305 RFC 8439 + decryption of `plain-chacha.ucxe` (T8) + tamper rejected |
| `verify-argon2.cjs` | BLAKE2b (RFC 7693) + Argon2id (cross-checked with argon2-cffi) + Argon2id derived key decryption of `plain-pass.ucxe` (T9) |
| `verify-ed25519.cjs` | SHA-512 + Ed25519 RFC 8032 section 7.1 vectors + cross-checked with Node crypto + tamper rejected |
| `verify-zip-integrity.cjs` | ZIP + INFLATE + BLAKE3 integrity cross-checked with `expected.json` (T4) + chapter text (T3) |
| `verify-ucxe.cjs` | Full UCXE decryption pipeline: T7/T8/T9 round-trip + T10 tamper (including reserved flag bit AAD binding) rejected |
| `verify-signatures.cjs` | Dual-layer signature verification of `sample-signed.ucx` -> status=VERIFIED, fingerprint=`c7eda2f7...d0` (T5); `sample.ucx` -> UNSIGNED (T6); tamper rejected |

Run:

```bash
node scripts/verify-argon2.cjs
node scripts/verify-ucxe.cjs
node scripts/verify-signatures.cjs
# ... and so on for the rest
```

`testdata/` contains self-contained fixture copies (copied from `sdk/testdata/`) for independent open-source use and offline testing.

## Versioning (ADR-012)

The SDK version number **X.Y.Z** means:

- **X.Y** = the **UCX standard version** supported by this SDK. Matching first two digits implies the same external API (same standard line).
- **Z** = the SDK's **patch number** on that standard line (bug fixes / implementation optimizations, without changing the supported standard version).

Older standard lines **continue to receive patches and are not deprecated** (analogous to Python maintaining multiple version lines simultaneously): for example, after the UCX standard upgrades to 0.5.x, patches such as `0.4.1`, `0.4.2`, etc. can still be released for the SDK supporting the 0.4.x standard.

> **Current version `0.4.0` corresponds to UCX standard 0.4.x.** Aligned with the parent project `ucx 0.4.0-alpha.2` wire-format and SDK contract.

The version format follows the parent project convention `x.y.z` (with optional `-alpha/beta/rc.N` pre-release suffix when necessary).

## License

`MIT` (consistent with the parent Unicodex project). See [LICENSE](./LICENSE).
