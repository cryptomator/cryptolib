/*******************************************************************************
 * Copyright (c) 2015, 2016 Sebastian Stenzel and others.
 * This file is licensed under the terms of the MIT license.
 * See the LICENSE.txt file for more info.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v1;

import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;
import org.cryptomator.cryptolib.common.MessageDigestSupplier;
import org.cryptomator.siv.SivMode;
import org.cryptomator.siv.UnauthenticCiphertextException;

import javax.crypto.IllegalBlockSizeException;

import static java.nio.charset.StandardCharsets.UTF_8;

class FileNameCryptorImpl implements FileNameCryptor {

	private static final BaseEncoding BASE32 = BaseEncoding.base32();
	private static final ThreadLocal<SivMode> AES_SIV = new ThreadLocal<SivMode>() {
		@Override
		protected SivMode initialValue() {
			return new SivMode();
		}
	};

	private final Masterkey masterkey;

	FileNameCryptorImpl(Masterkey masterkey) {
		this.masterkey = masterkey;
	}

	@Override
	public String hashDirectoryId(String cleartextDirectoryId) {
		try (DestroyableSecretKey ek = masterkey.getEncKey(); DestroyableSecretKey mk = masterkey.getMacKey();
			MessageDigestSupplier.ReusableMessageDigest sha1 = MessageDigestSupplier.SHA1.instance()) {
			byte[] cleartextBytes = cleartextDirectoryId.getBytes(UTF_8);
			byte[] encryptedBytes = AES_SIV.get().encrypt(ek, mk, cleartextBytes);
			byte[] hashedBytes = sha1.get().digest(encryptedBytes);
			return BASE32.encode(hashedBytes);
		}
	}

	@Override
	public String encryptFilename(BaseEncoding encoding, String cleartextName, byte[]... associatedData) {
		try (DestroyableSecretKey ek = masterkey.getEncKey(); DestroyableSecretKey mk = masterkey.getMacKey()) {
			byte[] cleartextBytes = cleartextName.getBytes(UTF_8);
			byte[] encryptedBytes = AES_SIV.get().encrypt(ek, mk, cleartextBytes, associatedData);
			return encoding.encode(encryptedBytes);
		}
	}

	@Override
	public String decryptFilename(BaseEncoding encoding, String ciphertextName, byte[]... associatedData) throws AuthenticationFailedException {
		try (DestroyableSecretKey ek = masterkey.getEncKey(); DestroyableSecretKey mk = masterkey.getMacKey()) {
			byte[] encryptedBytes = encoding.decode(ciphertextName);
			byte[] cleartextBytes = AES_SIV.get().decrypt(ek, mk, encryptedBytes, associatedData);
			return new String(cleartextBytes, UTF_8);
		} catch (UnauthenticCiphertextException | IllegalArgumentException | IllegalBlockSizeException e) {
			throw new AuthenticationFailedException("Invalid Ciphertext.", e);
		}
	}
}
