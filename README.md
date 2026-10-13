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

> **Draft for cryptolib 3.0.** The API shown here is under design; nothing below is implemented yet.

### Overview

| Type | Responsibility |
|---|---|
| `LockedVault` | Parsed but not yet authenticated `vault.cryptomator` / `vault.uvf`. Sealed: it is either a `Cvf8LockedVault` (tells you the `kid` of the required masterkey) or a `UvfLockedVault` (lists the recipients). `unlock(...)` yields the matching `UnlockedVault`. |
| `UnlockedVault` | An unlocked vault. Serializes its config, hands out `Directory` objects, owns the `FileContentCryptor`, encodes symlink targets. Sealed: `Cvf8UnlockedVault` (masterkey, cipher combo, shortening threshold) or `UvfUnlockedVault` (seed rotation, recipient management). |
| `VaultFormat` | `CVF8` or `UVF`. |

The sealed hierarchies are declared `sealed` in a Java 17 variant of the class files (multi-release jar), so consumers on Java 21+ can `switch` over them exhaustively; on Java 8 they are plain interfaces and `instanceof` does the job.
| `Directory` | One directory in the vault (its dirId and, for UVF, its seed). Computes the `d/XX/YYY` storage path and the path of its backup metadata file, encrypts/decrypts child names, produces the `dir.*` metadata bytes. |
| `EncryptedName` | Result of `Directory.encryptName`: the on-disk entry name, whether it was shortened, the inflated name for `name.c9s`, and the relative paths of the node's well-known files (`dir.*`, `symlink.*`, `contents.c9r`, `name.c9s`). |
| `FileContentCryptor` | Per-vault, stateless: chunk sizes, size/offset arithmetic, creating/opening per-file `EncryptedFile`s, and whole-buffer/stream/channel convenience. |
| `EncryptedFile` | One file: its (encrypted-once) header plus chunk encryption/decryption bound to that header. |
| `PerpetualMasterkey`, `UVFMasterkey`, `MasterkeyLoader` | Key material. `MasterkeyFileAccess` (package `common`) reads/writes `masterkey.cryptomator`. |

All examples assume `Path vaultDir` pointing at the vault's root directory and `SecureRandom csprng`. Exceptions in `org.cryptomator.cryptolib.api` are unchecked.

### Open an existing vault

`LockedVault.parse` detects the format from the file contents. CVF8 vaults are protected by a masterkey, whose `kid` is in the config and which a `MasterkeyLoader` resolves. UVF vaults are protected by one or more *recipients*; pick one and unlock with the matching secret:

```java
byte[] configBytes = Files.readAllBytes(configPath); // vault.cryptomator or vault.uvf
LockedVault locked = LockedVault.parse(configBytes);

UnlockedVault vault = switch (locked) { // Java 21+; exhaustive, no default needed
	case Cvf8LockedVault cvf8 -> {
		MasterkeyLoader keyLoader = keyId -> masterkeyFileAccess.load(vaultDir.resolve("masterkey.cryptomator"), passphrase);
		yield cvf8.unlock(keyLoader, csprng); // loads the key for cvf8.keyId(), verifies the signature, checks format == 8
	}
	case UvfLockedVault uvf -> {
		UvfRecipient recipient = uvf.recipients().stream()
				.filter(r -> "org.cryptomator.password".equals(r.kid()))
				.findAny().orElseThrow(NoSuchElementException::new);
		yield uvf.unlock(recipient, passphrase, csprng); // PBES2; or uvf.unlock(recipient, ecPrivateKey, csprng) for ECDH-ES
	}
};
```

On Java 8 the same code uses `instanceof` and casts. Unlocking with a wrong key/password throws `VaultKeyInvalidException`; an unsupported `format`/`uvf.spec.version` throws `UnsupportedVaultFormatException`. An `UnlockedVault` is likewise either a `Cvf8UnlockedVault` or a `UvfUnlockedVault`; format-agnostic code only needs `UnlockedVault`.

### Create a new vault

```java
// CVF8
try (PerpetualMasterkey masterkey = PerpetualMasterkey.generate(csprng)) {
	masterkeyFileAccess.persist(masterkey, vaultDir.resolve("masterkey.cryptomator"), passphrase);
	try (Cvf8UnlockedVault vault = Cvf8UnlockedVault.create(masterkey, 220, csprng)) { // new vaults always use SIV_GCM and kid "masterkeyfile:masterkey.cryptomator"
		Files.write(vaultDir.resolve(vault.configFileName()), vault.serializeConfig(), CREATE_NEW);
		createRootDirectory(vaultDir, vault);
	}
}

// UVF
try (UvfUnlockedVault vault = UvfUnlockedVault.create(csprng)) { // fresh KDF salt and initial seed
	vault.addPasswordRecipient("org.cryptomator.password", passphrase, 1_000_000);
	vault.addEcdhRecipient("org.cryptomator.hub.user.42", userPublicKey);
	Files.write(vaultDir.resolve(vault.configFileName()), vault.serializeConfig(), CREATE_NEW);
	createRootDirectory(vaultDir, vault);
}

static void createRootDirectory(Path vaultDir, UnlockedVault vault) throws IOException {
	Directory root = vault.rootDirectory();
	Path rootDir = vaultDir.resolve(root.dirPath()); // "d/XX/YYYYYYYYYYYYYYYYYYYYYYYYYYYYYY"
	Files.createDirectories(rootDir);
	Files.write(vaultDir.resolve(root.backupFilePath()), root.encryptedMetadataBackup()); // d/XX/YYY/dirid.c9r (UVF: dir.uvf)
}
```

### List a directory

```java
Directory dir = ...; // e.g. vault.rootDirectory()
try (DirectoryStream<Path> entries = Files.newDirectoryStream(vaultDir.resolve(dir.dirPath()))) {
	for (Path entry : entries) {
		String ciphertextName = entry.getFileName().toString();
		if (vault.isShortenedName(ciphertextName)) { // "*.c9s" (CVF8 only)
			ciphertextName = new String(Files.readAllBytes(entry.resolve("name.c9s")), UTF_8);
		}
		String cleartextName;
		try {
			cleartextName = dir.decryptName(ciphertextName); // "<base64url>.c9r" or "<base64url>.uvf"
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
EncryptedName name = dir.encryptName("Documents"); // deterministic; the same object you got when listing
Path parentDir = vaultDir.resolve(dir.dirPath());
byte[] dirFileContents = Files.readAllBytes(parentDir.resolve(name.dirFile())); // "<name>/dir.c9r" or "<name>/dir.uvf"
Directory subDir = vault.directory(dirFileContents);
Path subDirPath = vaultDir.resolve(subDir.dirPath());
```

`EncryptedName` knows the layout of a node: `name()` is the entry itself, `dirFile()`, `symlinkFile()`, `contentsFile()` and `inflatedNameFile()` are the paths of the well-known files below it, relative to the parent's `dirPath()`.

If the `dir.*` file is lost, the copy inside the content directory can be used instead: `vault.directoryFromBackup(Files.readAllBytes(vaultDir.resolve(subDir.backupFilePath())))`.

### Create a subdirectory

```java
Directory parent = ...;
Directory child = vault.newDirectory(); // fresh dirId (UVF: bound to latestSeed)

EncryptedName name = parent.encryptName("Documents");
Path parentDir = vaultDir.resolve(parent.dirPath());
Files.createDirectory(parentDir.resolve(name.name())); // "<b64>.c9r" or, if too long, "<sha1>.c9s"
if (name.isShortened()) {
	Files.write(parentDir.resolve(name.inflatedNameFile()), name.inflated().getBytes(UTF_8)); // "<sha1>.c9s/name.c9s"
}
Files.write(parentDir.resolve(name.dirFile()), child.encryptedMetadata()); // "<name>/dir.c9r" or "<name>/dir.uvf"

Path childDir = vaultDir.resolve(child.dirPath());
Files.createDirectories(childDir);
Files.write(vaultDir.resolve(child.backupFilePath()), child.encryptedMetadataBackup()); // "d/XX/YYY/dirid.c9r" or ".../dir.uvf"
```

Name encryption is deterministic, so callers may cache `encryptName` results. The maximum cleartext name length that fits a given filesystem limit is `vault.maxCleartextNameLength(maxCiphertextNameLength)`.

### Files: whole content, streams, channels

```java
FileContentCryptor fcc = vault.fileContentCryptor();

// whole buffer (small files, dir.uvf, symlinks)
byte[] ciphertext = fcc.encrypt("hello".getBytes(UTF_8));
byte[] cleartext = fcc.decrypt(ciphertext);

// streams and channels
try (OutputStream out = fcc.encryptingStream(Files.newOutputStream(ciphertextPath))) {
	out.write(cleartext);
}
try (ReadableByteChannel in = fcc.decryptingChannel(Files.newByteChannel(ciphertextPath))) {
	in.read(buffer);
}
```

### Files: random access via chunks

For a file system implementation, cryptolib exposes the header and chunk layer directly. `FileContentCryptor` does the arithmetic, `EncryptedFile` holds the per-file key:

```java
FileContentCryptor fcc = vault.fileContentCryptor();

// new file: header is created and encrypted exactly once
try (EncryptedFile file = fcc.createFile(); FileChannel ch = FileChannel.open(ciphertextPath, CREATE_NEW, WRITE)) {
	ch.write(file.encryptedHeader(), 0);
	ByteBuffer cleartextChunk = ...; // up to fcc.cleartextChunkSize() bytes
	long chunkIndex = fcc.chunkIndex(cleartextPosition);
	ch.write(file.encryptChunk(cleartextChunk, chunkIndex), fcc.ciphertextChunkOffset(chunkIndex));
}

// existing file
try (FileChannel ch = FileChannel.open(ciphertextPath, READ)) {
	ByteBuffer header = ByteBuffer.allocate(fcc.headerSize());
	ch.read(header, 0);
	header.flip();
	try (EncryptedFile file = fcc.openFile(header)) {
		ByteBuffer ciphertextChunk = ByteBuffer.allocate(fcc.ciphertextChunkSize());
		ch.read(ciphertextChunk, fcc.ciphertextChunkOffset(chunkIndex));
		ciphertextChunk.flip();
		ByteBuffer cleartextChunk = file.decryptChunk(ciphertextChunk, chunkIndex); // throws AuthenticationFailedException
	}
}

// sizes (both include the header)
long cleartextSize = fcc.cleartextSize(Files.size(ciphertextPath));
long ciphertextSize = fcc.ciphertextSize(cleartextSize);
long chunks = fcc.chunkCount(cleartextSize); // UVF: includes the empty EOF chunk when the size is a multiple of the chunk size
```

### Symlinks

```java
byte[] symlinkFileContents = vault.encryptSymlinkTarget("../target/file.txt");
Files.write(parentDir.resolve(name.symlinkFile()), symlinkFileContents); // "<name>/symlink.c9r" or "<name>/symlink.uvf"

String target = vault.decryptSymlinkTarget(Files.readAllBytes(parentDir.resolve(name.symlinkFile())));
```

### UVF: key rotation and recipients

```java
try (UvfUnlockedVault vault = uvfLocked.unlock(recipient, passphrase, csprng)) {
	vault.addSeed();                                              // new files and directories use the new seed
	vault.addEcdhRecipient("org.cryptomator.hub.user.43", key43); // grant access
	vault.removeRecipient("org.cryptomator.hub.user.42");         // drops the entry only; see Javadoc for what revocation requires
	Files.write(vaultDir.resolve("vault.uvf"), vault.serializeConfig(), TRUNCATE_EXISTING);
}
```

### Keys

`UnlockedVault` objects hold key material and implement `Destroyable`/`AutoCloseable`; use try-with-resources. `EncryptedFile` holds the file key and should be closed when the file is closed. `Cvf8UnlockedVault.masterkey()` (a `PerpetualMasterkey`) and `UvfUnlockedVault.masterkey()` (a `UVFMasterkey`) are available for applications that need raw key access, e.g. for Cryptomator Hub flows.

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
