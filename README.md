[![Build](https://github.com/cryptomator/cryptolib/workflows/Build/badge.svg)](https://github.com/cryptomator/cryptolib/actions?query=workflow%3ABuild)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=cryptomator_cryptolib&metric=alert_status)](https://sonarcloud.io/dashboard?id=cryptomator_cryptolib)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=cryptomator_cryptolib&metric=coverage)](https://sonarcloud.io/dashboard?id=cryptomator_cryptolib)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=cryptomator_cryptolib&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=cryptomator_cryptolib)
[![Maven Central](https://img.shields.io/maven-central/v/org.cryptomator/cryptolib.svg?maxAge=86400)](https://repo1.maven.org/maven2/org/cryptomator/cryptolib/)
[![Javadocs](http://www.javadoc.io/badge/org.cryptomator/cryptolib.svg)](http://www.javadoc.io/doc/org.cryptomator/cryptolib)

# Cryptomator Crypto Library

This library contains all cryptographic functions that are used by Cryptomator. The purpose of this project is to provide a separate light-weight library with its own release cycle that can be used in other projects, too.

cryptolib does "all but I/O": it understands the vault layout (config file, directory structure, file names, file contents) and operates on `byte[]`, `ByteBuffer`, `String`, channels and streams. Reading and writing actual files is left to the caller. Both the Cryptomator Vault Format 8 (CVF8) and the [Unified Vault Format](https://github.com/encryption-alliance/unified-vault-format) (UVF) are supported behind the same API.

## Usage

### Overview

| Type | Responsibility |
|---|---|
| `LockedVault` | Parsed but not yet authenticated `vault.cryptomator` / `vault.uvf`. Sealed: it is either a `Cvf8LockedVault` (tells you the `kid` of the required masterkey) or a `UvfLockedVault` (lists the recipients). `unlock(...)` yields the matching `UnlockedVault`. |
| `UnlockedVault` | An unlocked vault. Serializes its config, hands out `VaultDirectory` objects, creates/opens `VaultFile`s, encrypts whole files and streams, does the header/chunk size arithmetic, encodes symlink targets. Sealed: `Cvf8UnlockedVault` (masterkey, cipher combo, shortening threshold) or `UvfUnlockedVault` (seed rotation, recipient management). |
| `VaultDirectory` | One directory in the vault (its dirId and, for UVF, its seed). Computes the `d/XX/YYY` storage path and the path of its backup metadata file, encrypts/decrypts child names, produces the `dir.*` metadata bytes. |
| `VaultNode` | Result of `VaultDirectory.encryptName`: the on-disk entry name, whether it was shortened, the inflated name for `name.c9s`, the relative paths of the node's well-known files (`dir.*`, `symlink.*`, `contents.c9r`, `name.c9s`), plus `directory(reader)` / `symlinkTarget(reader)` to resolve and `createDirectory(child, writer)` / `createSymlink(target, writer)` to create them. |
| `VaultReader`, `VaultWriter` | Functional interfaces `byte[] read(String pathRelativeToVaultRoot)` and `void write(String pathRelativeToVaultRoot, byte[] contents)`. The only way cryptolib reads or writes vault metadata files (`name.c9s`, `dir.*`, `dirid.c9r`, `symlink.*`). A writer must create missing parent directories. |
| `VaultFile` | One open file: its (encrypted-once) header, file key and cleartext size. Positional `read`/`write`/`truncate` via `CiphertextReader`/`CiphertextWriter` callbacks, plus the raw chunk layer with its index/offset arithmetic. |
| `CiphertextReader`, `CiphertextWriter` | Functional interfaces shaped like `FileChannel.read(ByteBuffer, long)` / `write(ByteBuffer, long)`; the only way cryptolib touches a file's bytes. |
| `CvfMasterkey` | The 512-bit key of all Cryptomator Vault Format versions. `MasterkeyLoader` resolves a CVF8 config's `kid` to one; `MasterkeyFileAccess` (package `common`) reads/writes `masterkey.cryptomator`. UVF has no standalone key type: seeds live inside `vault.uvf` and are managed by `UvfUnlockedVault`. |
| `UvfLockedVault` / `UvfUnlockedVault` | `vault.uvf` has exactly two recipients: a key encryption key, either derived from a password with Argon2id (`org.cryptomator.password.argon2`) or a member key from Cryptomator Hub (`org.cryptomator.hub.memberkey`), and an EC recovery key (`org.cryptomator.hub.recoverykey.{jwk-thumbprint}`, whose public key is embedded in its entry). `unlock(password)`, `unlock(memberKey)`, `recover(privateKey)`; `setPassword`/`setMemberKey`/`setRecoveryKey` replace them. |

`LockedVault` and `UnlockedVault` are declared `sealed` in a Java 25 variant of their class files (multi-release jar), so consumers on Java 21+ can `switch` over them exhaustively; on Java 8 they are plain interfaces and `instanceof` does the job.

All examples assume `Path vaultDir` pointing at the vault's root directory, `SecureRandom csprng`, and these two callbacks through which cryptolib reads and writes metadata files:

```java
VaultReader reader = relPath -> Files.readAllBytes(vaultDir.resolve(relPath));
VaultWriter writer = (relPath, bytes) -> {
	Path file = vaultDir.resolve(relPath);
	Files.createDirectories(file.getParent());
	Files.write(file, bytes);
};
```

Exceptions in `org.cryptomator.cryptolib.api` are unchecked, except `IOException` passing through the callbacks.

### Open an existing vault

`LockedVault.parse` detects the format from the file contents. CVF8 vaults are protected by a masterkey, whose `kid` is in the config and which a `MasterkeyLoader` resolves. UVF vaults are protected by a password or a Hub member key, plus a recovery key:

```java
byte[] configBytes = Files.readAllBytes(configPath); // vault.cryptomator or vault.uvf
LockedVault locked = LockedVault.parse(configBytes);

UnlockedVault vault = switch (locked) { // Java 21+; exhaustive, no default needed
	case Cvf8LockedVault cvf8 -> {
		MasterkeyLoader keyLoader = keyId -> masterkeyFileAccess.load(vaultDir.resolve("masterkey.cryptomator"), passphrase);
		yield cvf8.unlock(keyLoader, csprng); // loads the key for cvf8.keyId(), verifies the signature, checks format == 8
	}
	case UvfLockedVault uvf -> yield uvf.unlock(passphrase, csprng); // or uvf.unlock(memberKey, csprng) for Hub vaults, see uvf.keyEncryptionKid()
};
```

On Java 8 the same code uses `instanceof` and casts. Unlocking with a wrong key/password throws `VaultKeyInvalidException`; an unsupported `format`/`uvf.spec.version` throws `UnsupportedVaultFormatException`. An `UnlockedVault` is likewise either a `Cvf8UnlockedVault` or a `UvfUnlockedVault`; format-agnostic code only needs `UnlockedVault`.

`UvfLockedVault.keyEncryptionKid()` tells whether the vault expects a password or a member key; `recover(ecPrivateKey, csprng)` unlocks it with the recovery key instead, e.g. to set a new password.

### Create a new vault

```java
// CVF8
try (CvfMasterkey masterkey = CvfMasterkey.generate(csprng)) {
	masterkeyFileAccess.persist(masterkey, vaultDir.resolve("masterkey.cryptomator"), passphrase);
	try (Cvf8UnlockedVault vault = Cvf8UnlockedVault.create(masterkey, 220, csprng)) { // new vaults always use SIV_GCM and kid "masterkeyfile:masterkey.cryptomator"
		writer.write(vault.configFileName(), vault.serializeConfig()); // vault.cryptomator
		vault.rootDirectory().writeMetadataBackup(writer);              // d/XX/YYY…/dirid.c9r
	}
}

// UVF
try (UvfUnlockedVault vault = UvfUnlockedVault.create(csprng)) { // fresh KDF salt and initial seed
	vault.setPassword(passphrase);          // Argon2id → A256KW; or vault.setMemberKey(aesKey) for Hub vaults
	vault.setRecoveryKey(recoveryPublicKey); // ECDH-ES+A256KW
	writer.write(vault.configFileName(), vault.serializeConfig()); // vault.uvf
	vault.rootDirectory().writeMetadataBackup(writer);              // d/XX/YYY…/dir.uvf
}
```

### List a directory

Whenever cryptolib needs the contents of a well-known file next to a node (`name.c9s`, `dir.c9r`, `symlink.uvf`, ...), it asks for it through the `VaultReader` callback. The consumer never has to know those file names.

```java
VaultDirectory dir = ...; // e.g. vault.rootDirectory()
try (DirectoryStream<Path> entries = Files.newDirectoryStream(vaultDir.resolve(dir.dirPath()))) {
	for (Path entry : entries) {
		String cleartextName;
		try {
			cleartextName = dir.decryptName(entry.getFileName().toString(), reader); // inflates shortened names via the reader when needed
		} catch (AuthenticationFailedException | IllegalArgumentException e) {
			continue; // not a vault node (e.g. dirid.c9r) or tampered
		}
		// Whether `entry` is a file, directory or symlink is decided by the caller
		// (presence of dir.c9r / symlink.c9r / contents.c9r in CVF8, dir.uvf / symlink.uvf in UVF).
	}
}
```

### Descend into a subdirectory

```java
VaultNode node = dir.encryptName("Documents"); // deterministic
VaultDirectory subDir = node.directory(reader); // reads "<dirPath>/<name>/dir.c9r" (or dir.uvf) through the callback
Path subDirPath = vaultDir.resolve(subDir.dirPath());

// equivalent, if you already hold the bytes:
VaultDirectory subDir2 = vault.directory(Files.readAllBytes(vaultDir.resolve(dir.dirPath()).resolve(node.dirFile())));
```

`VaultNode` knows the layout of a node: `name()` is the entry itself, `dirFile()`, `symlinkFile()`, `contentsFile()` and `inflatedNameFile()` are the paths of the well-known files below it, relative to the parent's `dirPath()`. A `VaultNode` is *not* a `VaultDirectory`: a node is an entry relative to its parent and may be a file, directory or symlink (the caller decides by looking at the files below it), whereas a `VaultDirectory` is identified by its dirId and is resolved from the `dir.*` contents. The root directory has no node at all.

If the `dir.*` file is lost, the copy inside the content directory can be used instead: `vault.directoryFromBackup(Files.readAllBytes(vaultDir.resolve(subDir.backupFilePath())))`.

### Create a subdirectory

```java
VaultDirectory parent = ...;
VaultDirectory child = vault.newDirectory();   // fresh dirId (UVF: bound to latestSeed)
VaultNode node = parent.encryptName("Documents");
node.createDirectory(child, writer);           // writes "<parent>/<name>/dir.*", "<parent>/<name>/name.c9s" if shortened, and "d/XX/YYY…/dirid.c9r|dir.uvf"
```

Without the writer, the same happens in pieces: `node.name()`, `node.inflatedNameFile()` + `node.inflated()`, `node.dirFile()` + `child.encryptedMetadata()`, `child.backupFilePath()` + `child.encryptedMetadataBackup()`. A file node is created by writing the content yourself (see below) to `node.contentsFile()` if `node.isShortened()`, else to `node.name()`.

Name encryption is deterministic, so callers may cache `encryptName` results. The maximum cleartext name length that fits a given filesystem limit is `vault.maxCleartextNameLength(maxCiphertextNameLength)`.

### Files: whole content, streams, channels

```java
// whole buffer (small files, dir.uvf, symlinks)
byte[] ciphertext = vault.encryptFile("hello".getBytes(UTF_8));
byte[] cleartext = vault.decryptFile(ciphertext);

// channels (the primitive; ByteBuffer-based, no extra copy)
try (WritableByteChannel out = vault.encryptingChannel(Files.newByteChannel(ciphertextPath, CREATE_NEW, WRITE))) {
	out.write(cleartextBuffer);
}
try (ReadableByteChannel in = vault.decryptingChannel(Files.newByteChannel(ciphertextPath))) {
	in.read(cleartextBuffer);
}

// streams (adapters for consumers that only have InputStream/OutputStream, e.g. cloud SDKs)
try (OutputStream out = vault.encryptingStream(cloudClient.upload(remotePath))) {
	out.write(cleartextBytes);
}
try (InputStream in = vault.decryptingStream(cloudClient.download(remotePath))) {
	in.read(cleartextBytes);
}
```

Both families write the header first and then whole chunks; the decrypting side authenticates every chunk and throws `AuthenticationFailedException` on tampering.

### Files: random access

An `VaultFile` represents one open file: its header (created and encrypted exactly once), the file key and the current cleartext size. Reads and writes at arbitrary cleartext positions are expressed against the *ciphertext* through two positional callbacks that mirror `FileChannel`'s `read(ByteBuffer, long)` and `write(ByteBuffer, long)`, so a `FileChannel` plugs in via method references. cryptolib does the chunk arithmetic, authenticates and decrypts the touched chunks, performs read-modify-write for partial chunks, zero-fills gaps when writing beyond the end, and maintains the UVF EOF chunk.

```java
// existing file
try (FileChannel ch = FileChannel.open(ciphertextPath, READ, WRITE)) {
	ByteBuffer header = ByteBuffer.allocate(vault.headerSize());
	ch.read(header, 0);
	header.flip();
	try (VaultFile file = vault.openFile(header, ch.size())) {
		ByteBuffer buf = ByteBuffer.allocate(4096);
		int read = file.read(1_000_000L, buf, ch::read);           // -1 at EOF; AuthenticationFailedException if a chunk was tampered
		file.write(file.size(), data, ch::read, ch::write);         // append
		file.truncate(100, ch::read, ch::write);                    // re-encrypts the last chunk ...
		ch.truncate(vault.ciphertextSize(100));                     // ... the caller cuts the channel
	}
}

// new file: size() == 0, header is written on the first write
try (FileChannel ch = FileChannel.open(ciphertextPath, CREATE_NEW, WRITE); VaultFile file = vault.createFile()) {
	file.write(0, data, ch::read, ch::write);
}

// sizes (both include the header); no file needs to be opened for these
long cleartextSize = vault.cleartextSize(Files.size(ciphertextPath));
long ciphertextSize = vault.ciphertextSize(cleartextSize);
```

Nothing is cached: every call touches the ciphertext through the callbacks. A file system with its own chunk cache uses the chunk layer below instead. All buffers are caller-provided; no method allocates and returns a `ByteBuffer`.

### Files: chunk layer

```java
VaultFile file = ...; // vault.createFile() or vault.openFile(header, ciphertextFileSize)

ch.write(file.encryptedHeader(), 0); // new file

long chunkIndex = file.chunkIndex(cleartextPosition);
int offsetInChunk = file.offsetInChunk(cleartextPosition);

ByteBuffer ciphertextChunk = ByteBuffer.allocate(vault.ciphertextChunkSize());
ByteBuffer cleartextChunk = ByteBuffer.allocate(vault.cleartextChunkSize());
ch.read(ciphertextChunk, file.ciphertextChunkOffset(chunkIndex));
ciphertextChunk.flip();
file.decryptChunk(ciphertextChunk, cleartextChunk, chunkIndex); // throws AuthenticationFailedException
cleartextChunk.flip();

file.encryptChunk(cleartextChunk, ciphertextChunk, chunkIndex);
ciphertextChunk.flip();
ch.write(ciphertextChunk, file.ciphertextChunkOffset(chunkIndex));

long chunks = file.chunkCount(cleartextSize); // UVF: includes the empty EOF chunk when the size is a multiple of the chunk size
```

### Symlinks

```java
VaultNode node = parent.encryptName("link");
node.createSymlink("../target/file.txt", writer); // writes "<parent>/<name>/symlink.c9r|symlink.uvf" (+ name.c9s if shortened)
String target = node.symlinkTarget(reader);       // reads it back

// byte-level equivalents: vault.encryptSymlinkTarget(String) / vault.decryptSymlinkTarget(byte[]) with node.symlinkFile()
```

### UVF: key rotation and recovery

```java
try (UvfUnlockedVault vault = uvfLocked.unlock(passphrase, csprng)) {
	vault.setPassword(newPassphrase); // or setMemberKey / setRecoveryKey
	vault.addSeed();                  // new files and directories use the new seed; do this whenever a secret is replaced, the old one's holder knows all existing seeds
	Files.write(vaultDir.resolve("vault.uvf"), vault.serializeConfig(), TRUNCATE_EXISTING);
}

// forgotten password: unlock with the recovery key and set a new one
try (UvfUnlockedVault vault = uvfLocked.recover(recoveryPrivateKey, csprng)) {
	vault.setPassword(newPassphrase);
	vault.addSeed();
	Files.write(vaultDir.resolve("vault.uvf"), vault.serializeConfig(), TRUNCATE_EXISTING);
}
```

Every `serializeConfig()` encrypts the metadata with a fresh content key for both recipients. The unlocked vault keeps what it needs for that: the key encryption key (the Argon2id output with its salt and cost parameters, or the member key) and the recovery key's public key from the file. Passwords are never retained.

### Keys

`UnlockedVault` objects hold key material and implement `Destroyable`/`AutoCloseable`; use try-with-resources. `VaultFile` holds the file key and should be closed when the file is closed. `Cvf8UnlockedVault.masterkey()` exposes the `CvfMasterkey` for applications that need raw key access, e.g. to re-persist `masterkey.cryptomator` with a new passphrase.

## Audits

- [Version 1.1.5 audit by Cure53](https://cryptomator.org/audits/2017-11-27%20crypto%20cure53.pdf)

| Finding | Comment |
|---|---|
| 1u1-22-001 | The now revoked GPG key has been used exclusively for the Maven repositories, was designed for signing only and was protected by a 30-character generated password (alphabet size: 96 chars). It was iterated and salted (SHA1 with 20971520 iterations), making even offline attacks very unattractive. Apart from that, this finding has no influence on the Tresor apps<sup>[1](#footnote-tresor-apps)</sup>. This was not known to Cure53 at the time of reporting. |
| 1u1-22-002 | This issue is related to [siv-mode](https://github.com/cryptomator/siv-mode/). |

## License

This project is dual-licensed under the AGPLv3 for FOSS projects as well as a commercial license derived from the LGPL for independent software vendors and resellers. If you want to use this library in applications that are *not* licensed under the AGPL, feel free to contact our [sales team](https://cryptomator.org/enterprise/).

---

<sup><a name="footnote-tresor-apps">1</a></sup> The Cure53 pentesting was performed during the development of the apps for 1&1 Mail & Media GmbH.
