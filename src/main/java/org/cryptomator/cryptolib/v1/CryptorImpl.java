/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v1;

import static org.cryptomator.cryptolib.v1.Constants.DEFAULT_SCRYPT_BLOCK_SIZE;
import static org.cryptomator.cryptolib.v1.Constants.DEFAULT_SCRYPT_COST_PARAM;
import static org.cryptomator.cryptolib.v1.Constants.DEFAULT_SCRYPT_SALT_LENGTH;
import static org.cryptomator.cryptolib.v1.Constants.KEY_LEN_BYTES;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.KeyFile;
import org.cryptomator.cryptolib.common.AesKeyWrap;
import org.cryptomator.cryptolib.common.MacSupplier;
import org.cryptomator.cryptolib.common.Scrypt;

class CryptorImpl implements Cryptor {

	private final SecretKey encKey;
	private final SecretKey macKey;
	private final SecureRandom random;
	private final FileContentCryptorImpl fileContentCryptor;
	private final FileHeaderCryptorImpl fileHeaderCryptor;
	private final FileNameCryptorImpl fileNameCryptor;

	/**
	 * Package-private constructor.
	 * Use {@link CryptorProviderImpl#createNew()} or {@link CryptorProviderImpl#createFromKeyFile(KeyFile, CharSequence, int)} to obtain a Cryptor instance.
	 */
	CryptorImpl(SecretKey encKey, SecretKey macKey, SecureRandom random) {
		this.encKey = encKey;
		this.macKey = macKey;
		this.random = random;
		this.fileHeaderCryptor = new FileHeaderCryptorImpl(encKey, macKey, random);
		this.fileContentCryptor = new FileContentCryptorImpl(macKey, random);
		this.fileNameCryptor = new FileNameCryptorImpl(encKey, macKey);
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
		// SecretKey did not implement Destroyable in Java 7:
		if (encKey instanceof Destroyable && macKey instanceof Destroyable) {
			return ((Destroyable) encKey).isDestroyed() || ((Destroyable) macKey).isDestroyed();
		} else {
			return false;
		}
	}

	@Override
	public void close() {
		destroy();
	}

	@Override
	public void destroy() {
		destroyQuietly(encKey);
		destroyQuietly(macKey);
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
			wrappedEncryptionKey = AesKeyWrap.wrap(kek, encKey);
			wrappedMacKey = AesKeyWrap.wrap(kek, macKey);
		} finally {
			Arrays.fill(kekBytes, (byte) 0x00);
		}

		final Mac mac = MacSupplier.HMAC_SHA256.withKey(macKey);
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
		byte[] rawEncKey = encKey.getEncoded();
		byte[] rawMacKeyKey = macKey.getEncoded();
		try {
			byte[] rawKey = new byte[rawEncKey.length + rawMacKeyKey.length];
			System.arraycopy(rawEncKey, 0, rawKey, 0, rawEncKey.length);
			System.arraycopy(rawMacKeyKey, 0, rawKey, rawEncKey.length, rawMacKeyKey.length);
			return rawKey;
		} finally {
			Arrays.fill(rawEncKey, (byte) 0x00);
			Arrays.fill(rawMacKeyKey, (byte) 0x00);
		}
	}

	private void destroyQuietly(SecretKey key) {
		try {
			if (key instanceof Destroyable && !((Destroyable) key).isDestroyed()) {
				((Destroyable) key).destroy();
			}
		} catch (DestroyFailedException e) {
			// ignore
		}
	}

	private void assertNotDestroyed() {
		if (isDestroyed()) {
			throw new IllegalStateException("Cryptor destroyed.");
		}
	}

}
