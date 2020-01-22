/*******************************************************************************
 * Copyright (c) 2015, 2016 Sebastian Stenzel and others.
 * This file is licensed under the terms of the MIT license.
 * See the LICENSE.txt file for more info.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v1;

import java.nio.charset.Charset;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.cryptomator.cryptolib.common.MessageDigestSupplier;
import org.cryptomator.siv.SivMode;
import org.cryptomator.siv.UnauthenticCiphertextException;

import com.google.common.io.BaseEncoding;

class FileNameCryptorImpl implements FileNameCryptor {

	private static final Charset UTF_8 = Charset.forName("UTF-8");
	private static final BaseEncoding BASE32 = BaseEncoding.base32();
	private static final ThreadLocal<SivMode> AES_SIV = new ThreadLocal<SivMode>() {
		@Override
		protected SivMode initialValue() {
			return new SivMode();
		};
	};

	private final SecretKey encryptionKey;
	private final SecretKey macKey;

	FileNameCryptorImpl(SecretKey encryptionKey, SecretKey macKey) {
		this.encryptionKey = encryptionKey;
		this.macKey = macKey;
	}

	@Override
	public String hashDirectoryId(String cleartextDirectoryId) {
		byte[] cleartextBytes = cleartextDirectoryId.getBytes(UTF_8);
		byte[] encryptedBytes = AES_SIV.get().encrypt(encryptionKey, macKey, cleartextBytes);
		byte[] hashedBytes = MessageDigestSupplier.SHA1.get().digest(encryptedBytes);
		return BASE32.encode(hashedBytes);
	}

	@Override
	public String encryptFilename(String cleartextName, byte[]... associatedData) {
		return encryptFilename(BASE32, cleartextName, associatedData);
	}

	@Override
	public String encryptFilename(BaseEncoding encoding, String cleartextName, byte[]... associatedData) {
		byte[] cleartextBytes = cleartextName.getBytes(UTF_8);
		byte[] encryptedBytes = AES_SIV.get().encrypt(encryptionKey, macKey, cleartextBytes, associatedData);
		return encoding.encode(encryptedBytes);
	}

	@Override
	public String decryptFilename(String ciphertextName, byte[]... associatedData) throws AuthenticationFailedException {
		return decryptFilename(BASE32, ciphertextName, associatedData);
	}

	@Override
	public String decryptFilename(BaseEncoding encoding, String ciphertextName, byte[]... associatedData) throws AuthenticationFailedException {
		try {
			byte[] encryptedBytes = encoding.decode(ciphertextName);
			byte[] cleartextBytes = AES_SIV.get().decrypt(encryptionKey, macKey, encryptedBytes, associatedData);
			return new String(cleartextBytes, UTF_8);
		} catch (UnauthenticCiphertextException | IllegalArgumentException | IllegalBlockSizeException e) {
			throw new AuthenticationFailedException("Invalid Ciphertext.", e);
		}
	}
}
