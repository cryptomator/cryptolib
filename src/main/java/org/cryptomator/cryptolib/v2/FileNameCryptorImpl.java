/*******************************************************************************
 * Copyright (c) 2015, 2016 Sebastian Stenzel and others.
 * This file is licensed under the terms of the MIT license.
 * See the LICENSE.txt file for more info.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v2;

import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.api.PerpetualMasterkey;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;
import org.cryptomator.cryptolib.common.MessageDigestSupplier;
import org.cryptomator.cryptolib.common.ObjectPool;
import org.cryptomator.siv.SivMode;
import org.cryptomator.siv.UnauthenticCiphertextException;

import javax.crypto.IllegalBlockSizeException;
import java.security.MessageDigest;

import static java.nio.charset.StandardCharsets.UTF_8;

class FileNameCryptorImpl implements FileNameCryptor {

	private static final BaseEncoding BASE32 = BaseEncoding.base32();
	private static final ObjectPool<SivMode> AES_SIV = new ObjectPool<>(SivMode::new);

	private final PerpetualMasterkey masterkey;

	FileNameCryptorImpl(PerpetualMasterkey masterkey) {
		this.masterkey = masterkey;
	}

	@Override
	public String hashDirectoryId(byte[] cleartextDirectoryId) {
		try (DestroyableSecretKey ek = masterkey.getEncKey(); DestroyableSecretKey mk = masterkey.getMacKey();
			 ObjectPool.Lease<MessageDigest> sha1 = MessageDigestSupplier.SHA1.instance();
			 ObjectPool.Lease<SivMode> siv = AES_SIV.get()) {
			byte[] encryptedBytes = siv.get().encrypt(ek, mk, cleartextDirectoryId);
			byte[] hashedBytes = sha1.get().digest(encryptedBytes);
			return BASE32.encode(hashedBytes);
		}
	}

	@Override
	public String encryptFilename(BaseEncoding encoding, String cleartextName, byte[]... associatedData) {
		try (DestroyableSecretKey ek = masterkey.getEncKey(); DestroyableSecretKey mk = masterkey.getMacKey();
			 ObjectPool.Lease<SivMode> siv = AES_SIV.get()) {
			byte[] cleartextBytes = cleartextName.getBytes(UTF_8);
			byte[] encryptedBytes = siv.get().encrypt(ek, mk, cleartextBytes, associatedData);
			return encoding.encode(encryptedBytes);
		}
	}

	@Override
	public String decryptFilename(BaseEncoding encoding, String ciphertextName, byte[]... associatedData) throws AuthenticationFailedException {
		try (DestroyableSecretKey ek = masterkey.getEncKey(); DestroyableSecretKey mk = masterkey.getMacKey();
			 ObjectPool.Lease<SivMode> siv = AES_SIV.get()) {
			byte[] encryptedBytes = encoding.decode(ciphertextName);
			byte[] cleartextBytes = siv.get().decrypt(ek, mk, encryptedBytes, associatedData);
			return new String(cleartextBytes, UTF_8);
		} catch (IllegalArgumentException | UnauthenticCiphertextException | IllegalBlockSizeException e) {
			throw new AuthenticationFailedException("Invalid Ciphertext.", e);
		}
	}

}
