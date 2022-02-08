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

public final class CipherSupplier {

	public static final CipherSupplier AES_CTR = new CipherSupplier("AES/CTR/NoPadding");
	public static final CipherSupplier AES_GCM = new CipherSupplier("AES/GCM/NoPadding");
	public static final CipherSupplier RFC3394_KEYWRAP = new CipherSupplier("AESWrap");

	private final String cipherAlgorithm;
	private final ObjectPool<Cipher> cipherPool;

	public CipherSupplier(String cipherAlgorithm) {
		this.cipherAlgorithm = cipherAlgorithm;
		this.cipherPool = new ObjectPool<>(this::createCipher);
		try (ObjectPool.Lease<Cipher> lease = cipherPool.get()) {
			lease.get(); // eagerly initialize to provoke exceptions
		}
	}

	private Cipher createCipher() {
		try {
			return Cipher.getInstance(cipherAlgorithm);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new IllegalArgumentException("Invalid cipher algorithm or padding.", e);
		}
	}

	/**
	 * Leases a reusable cipher object initialized for encryption.
	 *
	 * @param key    Encryption key
	 * @param params Params such as IV/Nonce
	 * @return A lease supplying a refurbished Cipher
	 */
	public ObjectPool.Lease<Cipher> encryptionCipher(SecretKey key, AlgorithmParameterSpec params) {
		ObjectPool.Lease<Cipher> lease = cipherPool.get();
		initMode(lease.get(), Cipher.ENCRYPT_MODE, key, params);
		return lease;
	}

	/**
	 * Creates a new Cipher object initialized for encryption.
	 *
	 * @param key    Encryption key
	 * @param params Params such as IV/Nonce
	 * @return New Cipher instance
	 * @deprecated Use {@link #encryptionCipher(SecretKey, AlgorithmParameterSpec)} instead.
	 */
	@Deprecated
	public Cipher forEncryption(SecretKey key, AlgorithmParameterSpec params) {
		final Cipher cipher = createCipher();
		initMode(cipher, Cipher.ENCRYPT_MODE, key, params);
		return cipher;
	}

	/**
	 * Leases a reusable cipher object initialized for decryption.
	 *
	 * @param key    Decryption key
	 * @param params Params such as IV/Nonce
	 * @return A lease supplying a refurbished Cipher
	 */
	public ObjectPool.Lease<Cipher> decryptionCipher(SecretKey key, AlgorithmParameterSpec params) {
		ObjectPool.Lease<Cipher> lease = cipherPool.get();
		initMode(lease.get(), Cipher.DECRYPT_MODE, key, params);
		return lease;
	}

	/**
	 * Creates a new Cipher object initialized for decryption.
	 *
	 * @param key    Encryption key
	 * @param params Params such as IV/Nonce
	 * @return New Cipher instance
	 * @deprecated Use {@link #decryptionCipher(SecretKey, AlgorithmParameterSpec)} instead.
	 */
	@Deprecated
	public Cipher forDecryption(SecretKey key, AlgorithmParameterSpec params) {
		final Cipher cipher = createCipher();
		initMode(cipher, Cipher.DECRYPT_MODE, key, params);
		return cipher;
	}

	/**
	 * Leases a reusable cipher object initialized for wrapping a key.
	 *
	 * @param kek Key encryption key
	 * @return A lease supplying a refurbished Cipher
	 */
	public ObjectPool.Lease<Cipher> keyWrapCipher(SecretKey kek) {
		ObjectPool.Lease<Cipher> lease = cipherPool.get();
		initMode(lease.get(), Cipher.WRAP_MODE, kek, null);
		return lease;
	}

	/**
	 * Creates a new Cipher object initialized for wrapping a key.
	 *
	 * @param kek Key encryption key
	 * @return New Cipher instance
	 * @deprecated Use {@link #keyWrapCipher(SecretKey)} instead.
	 */
	@Deprecated
	public Cipher forWrapping(SecretKey kek) {
		final Cipher cipher = createCipher();
		initMode(cipher, Cipher.WRAP_MODE, kek, null);
		return cipher;
	}

	/**
	 * Leases a reusable cipher object initialized for unwrapping a key.
	 *
	 * @param kek Key encryption key
	 * @return A lease supplying a refurbished Cipher
	 */
	public ObjectPool.Lease<Cipher> keyUnwrapCipher(SecretKey kek) {
		ObjectPool.Lease<Cipher> lease = cipherPool.get();
		initMode(lease.get(), Cipher.UNWRAP_MODE, kek, null);
		return lease;
	}

	/**
	 * Creates a new Cipher object initialized for unwrapping a key.
	 *
	 * @param kek Key encryption key
	 * @return New Cipher instance
	 * @deprecated Use {@link #keyUnwrapCipher(SecretKey)} instead.
	 */
	@Deprecated
	public Cipher forUnwrapping(SecretKey kek) {
		final Cipher cipher = createCipher();
		initMode(cipher, Cipher.UNWRAP_MODE, kek, null);
		return cipher;
	}

	private void initMode(Cipher cipher, int ciphermode, SecretKey key, AlgorithmParameterSpec params) {
		try {
			cipher.init(ciphermode, key, params);
		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException("Invalid key.", e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new IllegalArgumentException("Algorithm parameter not appropriate for " + cipher.getAlgorithm() + ".", e);
		}
	}

}