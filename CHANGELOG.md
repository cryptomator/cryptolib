# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

The changelog starts with version 2.2.2.
Changes to prior versions can be found on the [Github release page](https://github.com/cryptomator/cryptolib/releases).

## [Unreleased](https://github.com/cryptomator/cryptolib/compare/2.3.0...HEAD)

### Changed
* **Breaking:** complete redesign of the public API for version 3.0.0 ("all but I/O"). See the `Usage` section of the README.
* Unified Vault Format support (`vault.uvf`). A vault has two recipients: a key encryption key, derived from a password with Argon2id (BouncyCastle; kid `org.cryptomator.password.argon2`, parameters in the recipient header) or supplied by Cryptomator Hub as member key (kid `org.cryptomator.hub.memberkey`), and an EC recovery key (`org.cryptomator.hub.recoverykey.{jwk-thumbprint}`). Unlocking, recovery and re-encryption use nimbus' multi-recipient JWE API.
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

