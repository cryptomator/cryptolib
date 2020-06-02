/*******************************************************************************
 * Copyright (c) 2015, 2016 Sebastian Stenzel and others.
 * This file is licensed under the terms of the MIT license.
 * See the LICENSE.txt file for more info.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.api;

import com.google.common.io.BaseEncoding;

/**
 * Provides deterministic encryption capabilities as filenames must not change on subsequent encryption attempts,
 * otherwise each change results in major directory structure changes which would be a terrible idea for cloud storage encryption.
 * 
 * @see <a href="https://en.wikipedia.org/wiki/Deterministic_encryption">Wikipedia on deterministic encryption</a>
 */
public interface FileNameCryptor {

	/**
	 * @param cleartextDirectoryId an arbitrary directory id to be passed to one-way hash function
	 * @return constant length string, that is unlikely to collide with any other name.
	 */
	String hashDirectoryId(String cleartextDirectoryId);

	/**
	 * @param cleartextName original filename including cleartext file extension
	 * @param associatedData optional associated data, that will not get encrypted but needs to be provided during decryption
	 * @return encrypted filename without any file extension, encoded in BASE32
	 */
	String encryptFilename(String cleartextName, byte[]... associatedData);

	/**
	 * @param encoding Encoding to use to encode the returned ciphertext
	 * @param cleartextName original filename including cleartext file extension
	 * @param associatedData optional associated data, that will not get encrypted but needs to be provided during decryption
	 * @return encrypted filename without any file extension
	 */
	String encryptFilename(BaseEncoding encoding, String cleartextName, byte[]... associatedData);

	/**
	 * @param ciphertextName Ciphertext only, with any additional strings like file extensions stripped first, encoded in BASE32
	 * @param associatedData the same associated data used during encryption, otherwise and {@link AuthenticationFailedException} will be thrown
	 * @return cleartext filename, probably including its cleartext file extension.
	 * @throws AuthenticationFailedException if the ciphertext is malformed
	 */
	String decryptFilename(String ciphertextName, byte[]... associatedData) throws AuthenticationFailedException;

	/**
	 * @param encoding Encoding to use to decode <code>ciphertextName</code>
	 * @param ciphertextName Ciphertext only, with any additional strings like file extensions stripped first.
	 * @param associatedData the same associated data used during encryption, otherwise and {@link AuthenticationFailedException} will be thrown
	 * @return cleartext filename, probably including its cleartext file extension.
	 * @throws AuthenticationFailedException if the ciphertext is malformed
	 */
	String decryptFilename(BaseEncoding encoding, String ciphertextName, byte[]... associatedData) throws AuthenticationFailedException;

}
