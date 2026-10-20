# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

The changelog starts with version 2.2.2.
Changes to prior versions can be found on the [Github release page](https://github.com/cryptomator/cryptolib/releases).

## [Unreleased](https://github.com/cryptomator/cryptolib/compare/2.3.0...HEAD)

### Added
* Recovery keys as words: `UnlockedVault.serializedRecoveryKey()` encodes the CVF8 masterkey (44 words) or the UVF private recovery key (126 words, PKCS#8 as produced by Cryptomator Hub), `LockedVault.recover(words, csprng)` unlocks with them. The encoding (CRC32-based checksum, 4096-word dictionary, now `common.WordEncoder`) is the one used by Cryptomator and Cryptomator Hub. `UvfUnlockedVault.generateRecoveryKey(csprng)` and `setRecoveryKey(KeyPair)` let a vault retain its P-384 key pair for that.

### Removed
* All APIs deprecated in 2.x: `CipherSupplier.for*`, `MacSupplier.withKey`, `MessageDigestSupplier.get`, `MasterkeyFileAccess.readAllegedVaultVersion` and the `vaultVersion` parameter of `persist` (the file always records 999).
* `ObjectPool` and the pooling of `Cipher`/`Mac`/`MessageDigest` instances: `CipherSupplier`, `MacSupplier` and `MessageDigestSupplier` now return fresh JCA objects. On current JDKs instantiation costs well under a microsecond, which is negligible against the work per chunk, and the pool was a contention point under parallel load.
* `P384KeyPair`, `ECKeyPair`, `Pkcs12Helper` and the PKCS#12 exceptions. `X509CertBuilder` stays.
* The dependency on Guava (`com.google.guava:guava`, together with its `failureaccess` and `listenablefuture` artifacts). Base64 now uses `java.util.Base64`, the base32 directory hashes use BouncyCastle's `Base32`.

### Changed
* **Breaking:** complete redesign of the public API for version 3.0.0 ("all but I/O"). See the `Usage` section of the README.
* Unified Vault Format support (`vault.uvf`). A vault has two recipients: a key encryption key, derived from a password with Argon2id (BouncyCastle; kid `org.cryptomator.password.argon2`, parameters in the recipient header) or supplied by Cryptomator Hub as member key (kid `org.cryptomator.hub.memberkey`), and an EC recovery key (kid `org.cryptomator.recoverykey`). Unlocking, recovery and re-encryption use nimbus' multi-recipient JWE API.
* UVF specification update of 2026-10-20: recipient algorithms, the password recipient's Argon2 parameters and the recovery key's public JWK are committed in the encrypted payload (`recipientDetails`) and verified against the unprotected headers on unlock; public keys no longer appear in headers. Seed ids are derived from the seeds (`kdf(seed, 32, "seedDigest")[0..4]`) and verified. File headers use a per-node-type KDF context (`fileHeader`, `dirHeader`, `symlinkHeader`) and the spec version byte `1`. Seed pinning via `UvfLockedVault.requireSeeds(digests)` / `UvfUnlockedVault.seedDigests()` and `VaultRollbackException`. Replacing a password, member key or recovery key requires `addSeed()` before `serializeConfig()`, which otherwise returns the cached serialization while nothing changed. Decrypted names that are empty, `.`, `..` or contain `/` or NUL are rejected for both formats; UVF ciphertext names must be canonical base64url.
* BouncyCastle is no longer shaded into the jar; `org.bouncycastle:bcpkix-jdk18on` is now a regular (transitive) dependency.
* Added `com.nimbusds:nimbus-jose-jwt` as a dependency (vault config handling for `vault.cryptomator` and `vault.uvf`).
* Added `org.jspecify:jspecify` for nullness annotations; the public API is `@NullMarked` (`requires static org.jspecify` in the module descriptor).
* Multi-release jar now has exactly two layers: Java 8 (base) and Java 25 (`module-info`, sealed API roots). JDK 25 is required to build.


## [2.3.0](https://github.com/cryptomator/cryptolib/releases/tag/2.3.0) - 2026-10-12

### Added
* `MasterkeyFileValidator`: Overloaded `MasterkeyFileAccess::load` to apply custom checks (e.g. scrypt memory limits) to a masterkey file before key derivation ([#134](https://github.com/cryptomator/cryptolib/pull/134))

### Changed
* Masterkey files are now validated against upper scrypt parameter bounds (see `MasterkeyFileValidator.DEFAULT`) when loading them or changing their passphrase ([#133](https://github.com/cryptomator/cryptolib/issues/133))
* Scrypt now throws an `IllegalArgumentException` instead of an `OutOfMemoryError` if there is not enough memory for the given parameters
* Updated dependencies
    - Updated `org.bouncycastle:bcpkix-jdk18on` from 1.83 to 1.86
    - Updated `com.google.code.gson:gson` from 2.13.2 to 2.14.0
    - Updated `com.google.guava:guava` from 33.5.0-jre to 33.7.2-jre
    - Updated `org.slf4j:slf4j-api` from 2.0.17 to 2.0.20


## [2.2.2](https://github.com/cryptomator/cryptolib/releases/tag/2.2.2) - 2026-01-30

### Added
* Changelog file
* Maven wrapper script ([#103](https://github.com/cryptomator/cryptolib/pull/103))
* Locally reproducible builds ([#106](https://github.com/cryptomator/cryptolib/pull/106))

### Changed
* Pin CI actions ([#104](https://github.com/cryptomator/cryptolib/pull/104))
* Updated dependencies
    - Updated `org.bouncycastle:bcpkix-jdk18on` from 1.80 to 1.83
    - Updated `com.google.code.gson:gson` from 2.12.1 to 2.13.2
    - Updated `com.google.guava:guava` from 33.4.0-jre to 33.5.0-jre

