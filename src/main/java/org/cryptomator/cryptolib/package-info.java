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
 * // decrypt masterkey file:
 * byte[] masterkeyFile = Files.readAllBytes(pathToMasterkeyJsonFile);
 * String password = "dadada";
 * {@link org.cryptomator.cryptolib.Cryptor Cryptor} cryptor = {@link org.cryptomator.cryptolib.CryptorProvider#createFromKeyFile(byte[], CharSequence) CryptorProvider.createFromKeyFile(masterkeyFile, CharSequence)}.
 * 
 * // encrypt file:
 * ReadableByteChannel cleartextIn = ...;
 * SeekableByteChannel ciphertextOut = ...;
 * cryptor.{@link Cryptor#contents() contents()}.{@link org.cryptomator.cryptolib.FileContentCryptor#encryptFile(java.nio.channels.ReadableByteChannel, java.nio.channels.WritableByteChannel) encryptFile(cleartextIn, ciphertextOut)};
 * </pre>
 */
package org.cryptomator.cryptolib;