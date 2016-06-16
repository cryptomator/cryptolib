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
import static org.cryptomator.cryptolib.Constants.ENC_ALG;
import static org.cryptomator.cryptolib.Constants.KEY_LEN_BYTES;
import static org.cryptomator.cryptolib.Constants.MAC_ALG;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class CryptorProvider {

	private final SecureRandom random;
	private final KeyGenerator encKeyGen;
	private final KeyGenerator macKeyGen;

	public CryptorProvider(SecureRandom random) {
		this.random = random;
		try {
			this.encKeyGen = KeyGenerator.getInstance(ENC_ALG);
			encKeyGen.init(KEY_LEN_BYTES * Byte.SIZE, random);
			this.macKeyGen = KeyGenerator.getInstance(MAC_ALG);
			encKeyGen.init(KEY_LEN_BYTES * Byte.SIZE, random);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("Hard-coded algorithm doesn't exist.", e);
		}
	}

	/**
	 * @return A new Cryptor instance using randomized keys
	 */
	public Cryptor createNew() {
		SecretKey encKey = encKeyGen.generateKey();
		SecretKey macKey = macKeyGen.generateKey();
		return new Cryptor(encKey, macKey, random);
	}

	/**
	 * @param keyFileContents The bytes from a keyfile
	 * @param passphrase The passphrase to use for decrypting the keyfile
	 * @return A new Cryptor instance using the keys from the supplied keyfile
	 * @throws UnsupportedVaultFormatException If the vault has been created with an older or newer version.
	 * @throws InvalidPassphraseException If the key derived from the passphrase could not be used to decrypt the keyfile.
	 */
	public Cryptor createFromKeyFile(byte[] keyFileContents, CharSequence passphrase) throws UnsupportedVaultFormatException, InvalidPassphraseException {
		final KeyFile keyFile = KeyFile.parse(keyFileContents);
		final byte[] kekBytes = Scrypt.scrypt(passphrase, keyFile.getScryptSalt(), keyFile.getScryptCostParam(), keyFile.getScryptBlockSize(), KEY_LEN_BYTES);
		try {
			SecretKey kek = new SecretKeySpec(kekBytes, ENC_ALG);
			return createFromKeyFile(keyFile, kek);
		} finally {
			Arrays.fill(kekBytes, (byte) 0x00);
		}
	}

	private Cryptor createFromKeyFile(KeyFile keyFile, SecretKey kek) throws UnsupportedVaultFormatException, InvalidPassphraseException {
		// check version
		if (!CURRENT_VAULT_VERSION.equals(keyFile.getVersion())) {
			throw new UnsupportedVaultFormatException(keyFile.getVersion(), CURRENT_VAULT_VERSION);
		}

		try {
			SecretKey macKey = AesKeyWrap.unwrap(kek, keyFile.getMacMasterKey(), MAC_ALG);
			Mac mac = MacSupplier.HMAC_SHA256.withKey(macKey);
			byte[] versionMac = mac.doFinal(ByteBuffer.allocate(Integer.SIZE / Byte.SIZE).putInt(CURRENT_VAULT_VERSION).array());
			if (keyFile.getVersionMac() == null || !MessageDigest.isEqual(versionMac, keyFile.getVersionMac())) {
				// attempted downgrade attack: versionMac doesn't match version.
				throw new UnsupportedVaultFormatException(Integer.MAX_VALUE, CURRENT_VAULT_VERSION);
			}
			SecretKey encKey = AesKeyWrap.unwrap(kek, keyFile.getEncryptionMasterKey(), ENC_ALG);
			return new Cryptor(encKey, macKey, random);
		} catch (InvalidKeyException e) {
			throw new InvalidPassphraseException();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("Hard-coded algorithm doesn't exist.", e);
		}
	}

}
