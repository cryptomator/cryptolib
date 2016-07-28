/*******************************************************************************
    Cryptomator Crypto Library
    Copyright (C) 2016 Sebastian Stenzel and others.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *******************************************************************************/
/**
 * High-level encryption library used in Cryptomator.
 * <p>
 * Example Usage:
 * 
 * <pre>
 * // Create a SecureRandom instance (Java 8 example):
 * SecureRandom secRandom;
 * try {
 * 	// NIST SP 800-90A Rev 1 (http://dx.doi.org/10.6028/NIST.SP.800-90Ar1) suggests 440 seed bits for up to 2^48 bytes between reseeds for SHA1/SHA2 PRNGs:
 * 	secRandom = new ReseedingSecureRandom(SecureRandom.getInstanceStrong(), SecureRandom.getInstance("SHA1PRNG"), 1 << 30, 55);
 * } catch (NoSuchAlgorithmException e) {
 * 	throw new IllegalStateException("Used RNGs must exist in every Java platform.", e);
 * }
 * 
 * // Create new cryptor and save to masterkey file:
 * String password = "dadada";
 * {@link org.cryptomator.cryptolib.api.Cryptor Cryptor} cryptor = {@link org.cryptomator.cryptolib.Cryptors#version1(java.security.SecureRandom) Cryptors.version1(secRandom)}.{@link org.cryptomator.cryptolib.api.CryptorProvider#createNew() createNew()};
 * byte[] masterkeyFileContents = cryptor.{@link org.cryptomator.cryptolib.api.Cryptor#writeKeysToMasterkeyFile(CharSequence, int) writeKeysToMasterkeyFile(password, 42)};
 * Files.write(pathToMasterkeyJsonFile, masterkeyFileContents, WRITE, CREATE, TRUNCATE_EXISTING);
 * 
 * // Create Cryptor from existing masterkey file:
 * byte[] masterkeyFileContents = Files.readAllBytes(pathToMasterkeyJsonFile);
 * String password = "dadada";
 * Cryptor cryptor = {@link org.cryptomator.cryptolib.api.CryptorProvider#createFromKeyFile(byte[], CharSequence, int) CryptorProvider.createFromKeyFile(masterkeyFileContents, password, 42)};
 * 
 * // Encrypt and decrypt file name:
 * String uniqueIdOfDirectory = "87826cbd-344f-4df8-9c8d-af9bc769dfcf";
 * String cleartextFileName = "foo.txt";
 * String encryptedName = cryptor.{@link org.cryptomator.cryptolib.api.Cryptor#fileNameCryptor() fileNameCryptor()}.{@link org.cryptomator.cryptolib.api.FileNameCryptor#encryptFilename(String, byte[][])  encryptFilename(cleartextFileName, uniqueIdOfDirectory.getBytes())};
 * String decryptedName = cryptor.fileNameCryptor().{@link org.cryptomator.cryptolib.api.FileNameCryptor#decryptFilename(String, byte[][])  decryptFilename(encryptedName, uniqueIdOfDirectory.getBytes())};
 * 
 * // Encrypt file contents:
 * ByteBuffer plaintext = ...;
 * SeekableByteChannel ciphertextOut = ...;
 * try (WritableByteChannel ch = new {@link org.cryptomator.cryptolib.io.EncryptingWritableByteChannel EncryptingWritableByteChannel}(ciphertextOut, cryptor)) {
 * 	ch.write(plaintext);
 * }
 * 
 * // Decrypt file contents:
 * ReadableByteChannel ciphertextIn = ...;
 * try (ReadableByteChannel ch = new {@link org.cryptomator.cryptolib.io.DecryptingReadableByteChannel DecryptingReadableByteChannel}(ciphertextOut, cryptor, true)) {
 * 	ch.read(plaintext);
 * }
 * </pre>
 */
package org.cryptomator.cryptolib;
