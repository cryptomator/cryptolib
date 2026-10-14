/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.common;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Creates initialized {@link Cipher} instances for one transformation, translating the checked JCA exceptions into {@link IllegalArgumentException}s.
 */
public final class CipherSupplier {

	public static final CipherSupplier AES_CTR = new CipherSupplier("AES/CTR/NoPadding");
	public static final CipherSupplier AES_GCM = new CipherSupplier("AES/GCM/NoPadding");
	public static final CipherSupplier RFC3394_KEYWRAP = new CipherSupplier("AESWrap");

	private final String cipherAlgorithm;

	/**
	 * @param cipherAlgorithm The JCA transformation, e.g. {@code AES/GCM/NoPadding}
	 * @throws IllegalArgumentException If no provider supports it
	 */
	public CipherSupplier(String cipherAlgorithm) {
		this.cipherAlgorithm = cipherAlgorithm;
		createCipher(); // eagerly initialize to provoke exceptions
	}

	private Cipher createCipher() {
		try {
			return Cipher.getInstance(cipherAlgorithm);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new IllegalArgumentException("Invalid cipher algorithm or padding.", e);
		}
	}

	/**
	 * Creates a cipher initialized for encryption.
	 *
	 * @param key    Encryption key
	 * @param params Params such as IV/Nonce
	 * @return New cipher instance
	 */
	public Cipher encryptionCipher(SecretKey key, AlgorithmParameterSpec params) {
		return init(Cipher.ENCRYPT_MODE, key, params);
	}

	/**
	 * Creates a cipher initialized for decryption.
	 *
	 * @param key    Encryption key
	 * @param params Params such as IV/Nonce
	 * @return New cipher instance
	 */
	public Cipher decryptionCipher(SecretKey key, AlgorithmParameterSpec params) {
		return init(Cipher.DECRYPT_MODE, key, params);
	}

	/**
	 * Creates a cipher initialized for key wrapping.
	 *
	 * @param kek Key encryption key
	 * @return New cipher instance
	 */
	public Cipher keyWrapCipher(SecretKey kek) {
		return init(Cipher.WRAP_MODE, kek, null);
	}

	/**
	 * Creates a cipher initialized for key unwrapping.
	 *
	 * @param kek Key encryption key
	 * @return New cipher instance
	 */
	public Cipher keyUnwrapCipher(SecretKey kek) {
		return init(Cipher.UNWRAP_MODE, kek, null);
	}

	private Cipher init(int ciphermode, SecretKey key, AlgorithmParameterSpec params) {
		Cipher cipher = createCipher();
		try {
			cipher.init(ciphermode, key, params);
			return cipher;
		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException("Invalid key.", e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new IllegalArgumentException("Algorithm parameter not appropriate for " + cipher.getAlgorithm() + ".", e);
		}
	}

}
