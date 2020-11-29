/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v1;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.KeyFile;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.common.AesKeyWrap;
import org.cryptomator.cryptolib.common.MacSupplier;
import org.cryptomator.cryptolib.common.Scrypt;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.cryptomator.cryptolib.v1.Constants.DEFAULT_SCRYPT_BLOCK_SIZE;
import static org.cryptomator.cryptolib.v1.Constants.DEFAULT_SCRYPT_COST_PARAM;
import static org.cryptomator.cryptolib.v1.Constants.DEFAULT_SCRYPT_SALT_LENGTH;
import static org.cryptomator.cryptolib.v1.Constants.KEY_LEN_BYTES;

class CryptorImpl implements Cryptor {

	private final Masterkey masterkey;
	private final SecureRandom random;
	private final FileContentCryptorImpl fileContentCryptor;
	private final FileHeaderCryptorImpl fileHeaderCryptor;
	private final FileNameCryptorImpl fileNameCryptor;

	/**
	 * Package-private constructor.
	 * Use {@link CryptorProviderImpl#withKey(Masterkey)} to obtain a Cryptor instance.
	 */
	CryptorImpl(Masterkey masterkey, SecureRandom random) {
		this.masterkey = masterkey;
		this.random = random;
		this.fileHeaderCryptor = new FileHeaderCryptorImpl(masterkey.getEncKey(), masterkey.getMacKey(), random);
		this.fileContentCryptor = new FileContentCryptorImpl(masterkey.getMacKey(), random);
		this.fileNameCryptor = new FileNameCryptorImpl(masterkey.getEncKey(), masterkey.getMacKey());
	}

	@Override
	public FileContentCryptorImpl fileContentCryptor() {
		assertNotDestroyed();
		return fileContentCryptor;
	}

	@Override
	public FileHeaderCryptorImpl fileHeaderCryptor() {
		assertNotDestroyed();
		return fileHeaderCryptor;
	}

	@Override
	public FileNameCryptorImpl fileNameCryptor() {
		assertNotDestroyed();
		return fileNameCryptor;
	}

	@Override
	public boolean isDestroyed() {
		return masterkey.isDestroyed();
	}

	@Override
	public void close() {
		destroy();
	}

	@Override
	public void destroy() {
		masterkey.destroy();
	}

	@Override
	public KeyFile writeKeysToMasterkeyFile(CharSequence passphrase, int vaultVersion) {
		return writeKeysToMasterkeyFile(passphrase, new byte[0], vaultVersion);
	}

	@Override
	public KeyFile writeKeysToMasterkeyFile(CharSequence passphrase, byte[] pepper, int vaultVersion) {
		assertNotDestroyed();
		final byte[] salt = new byte[DEFAULT_SCRYPT_SALT_LENGTH];
		random.nextBytes(salt);
		final byte[] saltAndPepper = new byte[salt.length + pepper.length];
		System.arraycopy(salt, 0, saltAndPepper, 0, salt.length);
		System.arraycopy(pepper, 0, saltAndPepper, salt.length, pepper.length);

		final byte[] kekBytes = Scrypt.scrypt(passphrase, saltAndPepper, DEFAULT_SCRYPT_COST_PARAM, DEFAULT_SCRYPT_BLOCK_SIZE, KEY_LEN_BYTES);
		final byte[] wrappedEncryptionKey;
		final byte[] wrappedMacKey;
		try {
			final SecretKey kek = new SecretKeySpec(kekBytes, Constants.ENC_ALG);
			wrappedEncryptionKey = AesKeyWrap.wrap(kek, masterkey.getEncKey());
			wrappedMacKey = AesKeyWrap.wrap(kek, masterkey.getMacKey());
		} finally {
			Arrays.fill(kekBytes, (byte) 0x00);
		}

		final Mac mac = MacSupplier.HMAC_SHA256.withKey(masterkey.getMacKey());
		final byte[] versionMac = mac.doFinal(ByteBuffer.allocate(Integer.SIZE / Byte.SIZE).putInt(vaultVersion).array());

		final KeyFileImpl keyfile = new KeyFileImpl();
		keyfile.setVersion(vaultVersion);
		keyfile.scryptSalt = salt;
		keyfile.scryptCostParam = DEFAULT_SCRYPT_COST_PARAM;
		keyfile.scryptBlockSize = DEFAULT_SCRYPT_BLOCK_SIZE;
		keyfile.encryptionMasterKey = wrappedEncryptionKey;
		keyfile.macMasterKey = wrappedMacKey;
		keyfile.versionMac = versionMac;
		return keyfile;
	}

	@Override
	public byte[] getRawKey() {
		return masterkey.getEncoded();
	}

	private void assertNotDestroyed() {
		if (isDestroyed()) {
			throw new IllegalStateException("Cryptor destroyed.");
		}
	}

}
