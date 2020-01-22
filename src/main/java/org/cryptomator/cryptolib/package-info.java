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
 * // Create new cryptor and save to masterkey file:
 * String password = "dadada";
 * {@link org.cryptomator.cryptolib.api.Cryptor Cryptor} cryptor = {@link org.cryptomator.cryptolib.Cryptors#version1(java.security.SecureRandom) Cryptors.version1(SecureRandom.getInstanceStrong())}.{@link org.cryptomator.cryptolib.api.CryptorProvider#createNew() createNew()};
 * KeyFile keyFile = cryptor.{@link org.cryptomator.cryptolib.api.Cryptor#writeKeysToMasterkeyFile(CharSequence, int) writeKeysToMasterkeyFile(password, 42)};
 * byte[] masterkeyFileContents = keyFile.{@link org.cryptomator.cryptolib.api.KeyFile#serialize() serialize()};
 * Files.write(pathToMasterkeyJsonFile, masterkeyFileContents, WRITE, CREATE, TRUNCATE_EXISTING);
 * 
 * // Create Cryptor from existing masterkey file:
 * byte[] masterkeyFileContents = Files.readAllBytes(pathToMasterkeyJsonFile);
 * String password = "dadada";
 * KeyFile keyFile = KeyFile.{@link org.cryptomator.cryptolib.api.KeyFile#parse(byte[]) parse(masterkeyFileContents)}
 * Cryptor cryptor = {@link org.cryptomator.cryptolib.api.CryptorProvider#createFromKeyFile(org.cryptomator.cryptolib.api.KeyFile, java.lang.CharSequence, int) CryptorProvider.createFromKeyFile(keyFile, password, 42)};
 * 
 * // Each directory needs a (relatively) unique ID, which affects the encryption/decryption of child names:
 * String uniqueIdOfDirectory = UUID.randomUUID().toString();
 * 
 * // Encrypt and decrypt file name:
 * String cleartextFileName = "foo.txt";
 * String encryptedName = cryptor.{@link org.cryptomator.cryptolib.api.Cryptor#fileNameCryptor() fileNameCryptor()}.{@link org.cryptomator.cryptolib.api.FileNameCryptor#encryptFilename(String, byte[][])  encryptFilename(cleartextFileName, uniqueIdOfDirectory.getBytes())};
 * String decryptedName = cryptor.fileNameCryptor().{@link org.cryptomator.cryptolib.api.FileNameCryptor#decryptFilename(String, byte[][])  decryptFilename(encryptedName, uniqueIdOfDirectory.getBytes())};
 * 
 * // Encrypt file contents:
 * ByteBuffer plaintext = ...;
 * SeekableByteChannel ciphertextOut = ...;
 * try (WritableByteChannel ch = new {@link org.cryptomator.cryptolib.EncryptingWritableByteChannel EncryptingWritableByteChannel}(ciphertextOut, cryptor)) {
 * 	ch.write(plaintext);
 * }
 * 
 * // Decrypt file contents:
 * ReadableByteChannel ciphertextIn = ...;
 * try (ReadableByteChannel ch = new {@link org.cryptomator.cryptolib.DecryptingReadableByteChannel DecryptingReadableByteChannel}(ciphertextOut, cryptor, true)) {
 * 	ch.read(plaintext);
 * }
 * </pre>
 */
package org.cryptomator.cryptolib;
