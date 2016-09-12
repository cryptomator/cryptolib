/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.common;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

public class AesKeyWrap {

	/**
	 * @param kek Key encrypting key
	 * @param key Key to be wrapped
	 * @return Wrapped key
	 */
	public static byte[] wrap(SecretKey kek, SecretKey key) {
		try {
			final Cipher cipher = CipherSupplier.RFC3394_KEYWRAP.forWrapping(kek);
			return cipher.wrap(key);
		} catch (InvalidKeyException | IllegalBlockSizeException e) {
			throw new IllegalArgumentException("Unable to wrap key.", e);
		}
	}

	/**
	 * @param kek Key encrypting key
	 * @param wrappedKey Key to be unwrapped
	 * @param wrappedKeyAlgorithm Key designation, i.e. algorithm to be associated with the unwrapped key.
	 * @return Unwrapped key
	 * @throws InvalidKeyException If unwrapping failed (i.e. wrong kek)
	 */
	public static SecretKey unwrap(SecretKey kek, byte[] wrappedKey, String wrappedKeyAlgorithm) throws InvalidKeyException {
		return unwrap(kek, wrappedKey, wrappedKeyAlgorithm, Cipher.SECRET_KEY);
	}

	// visible for testing
	static SecretKey unwrap(SecretKey kek, byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType) throws InvalidKeyException {
		final Cipher cipher = CipherSupplier.RFC3394_KEYWRAP.forUnwrapping(kek);
		try {
			return (SecretKey) cipher.unwrap(wrappedKey, wrappedKeyAlgorithm, wrappedKeyType);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalArgumentException("Invalid algorithm: " + wrappedKeyAlgorithm, e);
		}
	}

}
