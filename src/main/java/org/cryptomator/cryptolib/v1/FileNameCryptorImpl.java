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

import javax.crypto.AEADBadTagException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.BaseNCodec;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.cryptomator.cryptolib.common.MessageDigestSupplier;
import org.cryptomator.siv.SivMode;

class FileNameCryptorImpl implements FileNameCryptor {

	private static final Charset UTF_8 = Charset.forName("UTF-8");
	private static final BaseNCodec BASE32 = new Base32();
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
		return BASE32.encodeAsString(hashedBytes);
	}

	@Override
	public String encryptFilename(String cleartextName, byte[]... associatedData) {
		byte[] cleartextBytes = cleartextName.getBytes(UTF_8);
		byte[] encryptedBytes = AES_SIV.get().encrypt(encryptionKey, macKey, cleartextBytes, associatedData);
		return BASE32.encodeAsString(encryptedBytes);
	}

	@Override
	public String decryptFilename(String ciphertextName, byte[]... associatedData) throws AuthenticationFailedException {
		try {
			byte[] encryptedBytes = BASE32.decode(ciphertextName);
			byte[] cleartextBytes = AES_SIV.get().decrypt(encryptionKey, macKey, encryptedBytes, associatedData);
			return new String(cleartextBytes, UTF_8);
		} catch (AEADBadTagException | IllegalBlockSizeException e) {
			throw new AuthenticationFailedException("Invalid Ciphertext.", e);
		}
	}

}
