/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib;

import static org.cryptomator.cryptolib.Constants.CURRENT_VAULT_VERSION;
import static org.cryptomator.cryptolib.Constants.DEFAULT_SCRYPT_BLOCK_SIZE;
import static org.cryptomator.cryptolib.Constants.DEFAULT_SCRYPT_COST_PARAM;
import static org.cryptomator.cryptolib.Constants.DEFAULT_SCRYPT_SALT_LENGTH;
import static org.cryptomator.cryptolib.Constants.KEY_LEN_BYTES;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

public class Cryptor implements Destroyable {

	private final SecretKey encKey;
	private final SecretKey macKey;
	private final SecureRandom random;
	private final FileContentCryptor fileContentCryptor;

	/**
	 * Package-private constructor.
	 * Use {@link CryptorProvider#createNew()} or {@link CryptorProvider#createFromKeyFile(byte[], CharSequence)} to obtain a Cryptor instance.
	 */
	Cryptor(SecretKey encryptionKey, SecretKey macKey, SecureRandom random) {
		this.encKey = encryptionKey;
		this.macKey = macKey;
		this.random = random;
		this.fileContentCryptor = new FileContentCryptor(encryptionKey, macKey, random);
	}

	public FileContentCryptor contents() {
		return fileContentCryptor;
	}

	@Override
	public boolean isDestroyed() {
		return encKey.isDestroyed() && macKey.isDestroyed();
	}

	@Override
	public void destroy() {
		destroyQuietly(encKey);
		destroyQuietly(macKey);
	}

	public byte[] writeKeysToMasterkeyFile(CharSequence passphrase) {
		final byte[] scryptSalt = new byte[DEFAULT_SCRYPT_SALT_LENGTH];
		random.nextBytes(scryptSalt);

		final byte[] kekBytes = Scrypt.scrypt(passphrase, scryptSalt, DEFAULT_SCRYPT_COST_PARAM, DEFAULT_SCRYPT_BLOCK_SIZE, KEY_LEN_BYTES);
		final byte[] wrappedEncryptionKey;
		final byte[] wrappedMacKey;
		try {
			final SecretKey kek = new SecretKeySpec(kekBytes, Constants.ENC_ALG);
			wrappedEncryptionKey = AesKeyWrap.wrap(kek, encKey);
			wrappedMacKey = AesKeyWrap.wrap(kek, macKey);
			destroyQuietly(kek);
		} finally {
			Arrays.fill(kekBytes, (byte) 0x00);
		}

		final Mac mac = MacSupplier.HMAC_SHA256.withKey(macKey);
		final byte[] versionMac = mac.doFinal(ByteBuffer.allocate(Integer.BYTES).putInt(CURRENT_VAULT_VERSION).array());

		final KeyFile keyfile = new KeyFile();
		keyfile.setVersion(CURRENT_VAULT_VERSION);
		keyfile.setScryptSalt(scryptSalt);
		keyfile.setScryptCostParam(DEFAULT_SCRYPT_COST_PARAM);
		keyfile.setScryptBlockSize(DEFAULT_SCRYPT_BLOCK_SIZE);
		keyfile.setEncryptionMasterKey(wrappedEncryptionKey);
		keyfile.setMacMasterKey(wrappedMacKey);
		keyfile.setVersionMac(versionMac);
		return keyfile.serialize();
	}

	private void destroyQuietly(Destroyable d) {
		try {
			d.destroy();
		} catch (DestroyFailedException e) {
			// ignore
		}
	}

}
