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
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class AesKeyWrap {

	private AesKeyWrap() {
	}

	/**
	 * @param kek Key encrypting key
	 * @param key Key to be wrapped
	 * @return Wrapped key
	 */
	public static byte[] wrap(DestroyableSecretKey kek, SecretKey key) {
		try (DestroyableSecretKey kekCopy = kek.copy();
			 ObjectPool.Lease<Cipher> cipher = CipherSupplier.RFC3394_KEYWRAP.keyWrapCipher(kekCopy)) {
			return cipher.get().wrap(key);
		} catch (InvalidKeyException | IllegalBlockSizeException e) {
			throw new IllegalArgumentException("Unable to wrap key.", e);
		}
	}

	/**
	 * @param kek                 Key encrypting key
	 * @param wrappedKey          Key to be unwrapped
	 * @param wrappedKeyAlgorithm Key designation, i.e. algorithm to be associated with the unwrapped key.
	 * @return Unwrapped key
	 * @throws InvalidKeyException If unwrapping failed (i.e. wrong kek)
	 */
	public static DestroyableSecretKey unwrap(DestroyableSecretKey kek, byte[] wrappedKey, String wrappedKeyAlgorithm) throws InvalidKeyException {
		return unwrap(kek, wrappedKey, wrappedKeyAlgorithm, Cipher.SECRET_KEY);
	}

	// visible for testing
	static DestroyableSecretKey unwrap(DestroyableSecretKey kek, byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType) throws InvalidKeyException {
		try (DestroyableSecretKey kekCopy = kek.copy();
			 ObjectPool.Lease<Cipher> cipher = CipherSupplier.RFC3394_KEYWRAP.keyUnwrapCipher(kekCopy)) {
			return DestroyableSecretKey.from(cipher.get().unwrap(wrappedKey, wrappedKeyAlgorithm, wrappedKeyType));
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalArgumentException("Invalid algorithm: " + wrappedKeyAlgorithm, e);
		}
	}

}
