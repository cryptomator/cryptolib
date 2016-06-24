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
 * {@link org.cryptomator.cryptolib.Cryptor Cryptor} cryptor = {@link org.cryptomator.cryptolib.CryptorProvider#createNew() CryptorProvider.createNew()};
 * byte[] masterkeyFileContents = cryptor.{@link org.cryptomator.cryptolib.Cryptor#writeKeysToMasterkeyFile(CharSequence) writeKeysToMasterkeyFile(password)};
 * Files.write(pathToMasterkeyJsonFile, masterkeyFileContents, WRITE, CREATE, TRUNCATE_EXISTING);
 * 
 * // Create Cryptor from existing masterkey file:
 * byte[] masterkeyFileContents = Files.readAllBytes(pathToMasterkeyJsonFile);
 * String password = "dadada";
 * Cryptor cryptor = {@link org.cryptomator.cryptolib.CryptorProvider#createFromKeyFile(byte[], CharSequence) CryptorProvider.createFromKeyFile(masterkeyFileContents, password)};
 * 
 * // Encrypt and decrypt file name:
 * String uniqueIdOfDirectory = "87826cbd-344f-4df8-9c8d-af9bc769dfcf";
 * String cleartextFileName = "foo.txt";
 * String encryptedName = cryptor.{@link org.cryptomator.cryptolib.Cryptor#fileNameCryptor() fileNameCryptor()}.{@link org.cryptomator.cryptolib.FileNameCryptor#encryptFilename(String, byte[][])  encryptFilename(cleartextFileName, uniqueIdOfDirectory.getBytes())};
 * String decryptedName = cryptor.fileNameCryptor().{@link org.cryptomator.cryptolib.FileNameCryptor#decryptFilename(String, byte[][])  encryptFilename(encryptedName, uniqueIdOfDirectory.getBytes())};
 * 
 * // Encrypt file contents:
 * ReadableByteChannel cleartextIn = ...;
 * SeekableByteChannel ciphertextOut = ...;
 * cryptor.{@link org.cryptomator.cryptolib.Cryptor#fileContentCryptor() fileContentCryptor()}.{@link org.cryptomator.cryptolib.FileContentCryptor#encryptFile(java.nio.channels.ReadableByteChannel, java.nio.channels.SeekableByteChannel) encryptFile(cleartextIn, ciphertextOut)};
 * 
 * // Decrypt file contents:
 * ReadableByteChannel ciphertextIn = ...;
 * WritableByteChannel cleartextOut = ...;
 * cryptor.fileContentCryptor().{@link org.cryptomator.cryptolib.FileContentCryptor#decryptFile(java.nio.channels.ReadableByteChannel, java.nio.channels.WritableByteChannel, boolean) decryptFile(ciphertextIn, cleartextOut, true)};
 * </pre>
 */
package org.cryptomator.cryptolib;