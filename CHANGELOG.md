# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

The changelog starts with version 2.2.2.
Changes to prior versions can be found on the [Github release page](https://github.com/cryptomator/cryptolib/releases).

## [Unreleased](https://github.com/cryptomator/cryptolib/compare/2.4.0...HEAD)

### Added
* `DirectoryContentCryptor::encryptSymlinkTarget` / `decryptSymlinkTarget` for UVF symlink metadata (`symlink.uvf`), encrypted under the `symlinkHeader` key context
* `UVFMasterkey::seedDigests`, `seedDigest` and `seedId` for seed pinning and seed ID derivation

### Changed
* The experimental UVF implementation (`CryptorProvider.Scheme.UVF_DRAFT`) now follows the [UVF spec](https://github.com/encryption-alliance/unified-vault-format) as of 2026-10-20, which changes the on-disk format of existing draft vaults:
    - seed IDs are derived from the seeds (`kdf(seed, 32, "seedDigest")[0..4]`) and verified when parsing the vault metadata payload, which is now validated as required by the spec (seed and salt lengths, `initialSeed`/`latestSeed` present, canonical base64url)
    - file header version byte is `1`; chunks carry 32740 payload bytes and use a 4 byte big-endian chunk number as AAD; an empty EOF chunk terminates files whose size is a multiple of the chunk size
    - header keys are derived per node type (`fileHeader`, `dirHeader`, `symlinkHeader`)
    - ciphertext names are unpadded base64url and must decode canonically; cleartext names are NFC-normalized and rejected if empty, `.`, `..` or containing `/` or NUL
* `DecryptingReadableByteChannel` validates the ciphertext structure (e.g. the UVF EOF chunk) when reading a whole file
* The JWE layer of `vault.uvf` (protected header and recipient validation, `recipientDetails`, re-wrapping with a fresh CEK) and the persistence of seed pins remain the responsibility of the library consumer


## [2.4.0](https://github.com/cryptomator/cryptolib/releases/tag/2.4.0) - 2026-10-26

### Added
* Overloaded `MasterkeyFileAccess::changePassphrase` to apply a custom `MasterkeyFileValidator` ([#141](https://github.com/cryptomator/cryptolib/pull/141))

### Changed
* `MasterkeyFileAccess::changePassphrase` now rejects structurally invalid masterkey files with an `IOException` before validating them ([#141](https://github.com/cryptomator/cryptolib/pull/141))


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

