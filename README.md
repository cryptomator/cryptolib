[![Build Status](https://travis-ci.org/cryptomator/cryptolib.svg?branch=master)](https://travis-ci.org/cryptomator/cryptolib)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/9d736fe3e9e14dfb8a65949abbe8f712)](https://www.codacy.com/app/cryptomator/cryptolib)
[![Codacy Badge](https://api.codacy.com/project/badge/Coverage/9d736fe3e9e14dfb8a65949abbe8f712)](https://www.codacy.com/app/cryptomator/cryptolib?utm_source=github.com&utm_medium=referral&utm_content=cryptomator/cryptolib&utm_campaign=Badge_Coverage)
[![Known Vulnerabilities](https://snyk.io/test/github/cryptomator/cryptolib/badge.svg)](https://snyk.io/test/github/cryptomator/cryptolib)
[![Maven Central](https://img.shields.io/maven-central/v/org.cryptomator/cryptolib.svg?maxAge=86400)](https://repo1.maven.org/maven2/org/cryptomator/cryptolib/)
[![Javadocs](http://www.javadoc.io/badge/org.cryptomator/cryptolib.svg)](http://www.javadoc.io/doc/org.cryptomator/cryptolib)

# Cryptomator Crypto Library

This library contains all cryptographic functions that are used by Cryptomator. The purpose of this project is to provide a separate light-weight library with its own release cycle that can be used in other projects, too.

## Audits

- [Version 1.1.5 audit by Cure53](https://cryptomator.org/audits/2017-11-27%20crypto%20cure53.pdf)

| Finding | Comment |
|---|---|
| 1u1-22-001 | The GPG key is used exclusively for the Maven repositories, is designed for signing only and is protected by a 30-character generated password (alphabet size: 96 chars). It is iterated and salted (SHA1 with 20971520 iterations). An offline attack is also very unattractive. Apart from that, this finding has no influence on the Tresor apps<sup>[1](#footnote-tresor-apps)</sup>. This was not known to Cure53 at the time of reporting. |
| 1u1-22-002 | This issue is related to [siv-mode](https://github.com/cryptomator/siv-mode/). |

## License

This project is dual-licensed under the AGPLv3 for FOSS projects as well as a commercial license derived from the LGPL for independent software vendors and resellers. If you want to use this library in applications that are *not* licensed under the AGPL, feel free to contact our [sales team](https://cryptomator.org/enterprise/).

---

<sup><a name="footnote-tresor-apps">1</a></sup> The Cure53 pentesting was performed during the development of the apps for 1&1 Mail & Media GmbH.
