/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

final class AesKeyWrap {

	private static final String RFC3394_CIPHER = "AESWrap";

	private AesKeyWrap() {
	}

	/**
	 * @param kek Key encrypting key
	 * @param key Key to be wrapped
	 * @return Wrapped key
	 */
	public static byte[] wrap(SecretKey kek, SecretKey key) {
		final Cipher cipher;
		try {
			cipher = Cipher.getInstance(RFC3394_CIPHER);
			cipher.init(Cipher.WRAP_MODE, kek);
		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException("Invalid key.", e);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new IllegalStateException("Algorithm/Padding should exist.", e);
		}

		try {
			return cipher.wrap(key);
		} catch (InvalidKeyException | IllegalBlockSizeException e) {
			throw new IllegalStateException("Unable to wrap key.", e);
		}
	}

	/**
	 * @param kek Key encrypting key
	 * @param wrappedKey Key to be unwrapped
	 * @param wrappedKeyAlgorithm Key designation, i.e. algorithm name to be associated with the unwrapped key.
	 * @return Unwrapped key
	 * @throws NoSuchAlgorithmException If keyAlgorithm is unknown
	 * @throws InvalidKeyException If unwrapping failed (i.e. wrong kek)
	 */
	public static SecretKey unwrap(SecretKey kek, byte[] wrappedKey, String wrappedKeyAlgorithm) throws InvalidKeyException, NoSuchAlgorithmException {
		final Cipher cipher;
		try {
			cipher = Cipher.getInstance(RFC3394_CIPHER);
			cipher.init(Cipher.UNWRAP_MODE, kek);
		} catch (InvalidKeyException ex) {
			throw new IllegalArgumentException("Invalid key.", ex);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
			throw new IllegalStateException("Algorithm/Padding should exist.", ex);
		}

		return (SecretKey) cipher.unwrap(wrappedKey, wrappedKeyAlgorithm, Cipher.SECRET_KEY);
	}

}
