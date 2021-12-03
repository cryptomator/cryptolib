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
		try (ObjectPool<Cipher>.Lease lease = cipherPool.get()) {
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

	public ReusableCipher encrypt(SecretKey key, AlgorithmParameterSpec params) {
		ObjectPool<Cipher>.Lease lease = cipherPool.get();
		initMode(lease.get(), Cipher.ENCRYPT_MODE, key, params);
		return new ReusableCipher(lease);
	}

	@Deprecated
	public Cipher forEncryption(SecretKey key, AlgorithmParameterSpec params) {
		final Cipher cipher = createCipher();
		initMode(cipher, Cipher.ENCRYPT_MODE, key, params);
		return cipher;
	}

	public ReusableCipher decrypt(SecretKey key, AlgorithmParameterSpec params) {
		ObjectPool<Cipher>.Lease lease = cipherPool.get();
		initMode(lease.get(), Cipher.DECRYPT_MODE, key, params);
		return new ReusableCipher(lease);
	}

	@Deprecated
	public Cipher forDecryption(SecretKey key, AlgorithmParameterSpec params) {
		final Cipher cipher = createCipher();
		initMode(cipher, Cipher.DECRYPT_MODE, key, params);
		return cipher;
	}

	public ReusableCipher wrap(SecretKey kek) {
		ObjectPool<Cipher>.Lease lease = cipherPool.get();
		initMode(lease.get(), Cipher.WRAP_MODE, kek, null);
		return new ReusableCipher(lease);
	}

	@Deprecated
	public Cipher forWrapping(SecretKey kek) {
		final Cipher cipher = createCipher();
		initMode(cipher, Cipher.WRAP_MODE, kek, null);
		return cipher;
	}

	public ReusableCipher unwrap(SecretKey kek) {
		ObjectPool<Cipher>.Lease lease = cipherPool.get();
		initMode(lease.get(), Cipher.UNWRAP_MODE, kek, null);
		return new ReusableCipher(lease);
	}

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

	public static class ReusableCipher implements AutoCloseable {

		private final ObjectPool<Cipher>.Lease lease;

		private ReusableCipher(ObjectPool<Cipher>.Lease lease) {
			this.lease = lease;
		}

		public Cipher get() {
			return lease.get();
		}

		@Override
		public void close() {
			lease.close();
		}
	}
}