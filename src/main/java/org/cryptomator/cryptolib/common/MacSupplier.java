/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.common;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Creates keyed {@link Mac} instances for one algorithm, translating the checked JCA exceptions into {@link IllegalArgumentException}s.
 */
public final class MacSupplier {

	public static final MacSupplier HMAC_SHA256 = new MacSupplier("HmacSHA256");

	private final String macAlgorithm;

	/**
	 * @param macAlgorithm The JCA MAC algorithm, e.g. {@code HmacSHA256}
	 * @throws IllegalArgumentException If no provider supports it
	 */
	public MacSupplier(String macAlgorithm) {
		this.macAlgorithm = macAlgorithm;
		createMac(); // eagerly initialize to provoke exceptions
	}

	private Mac createMac() {
		try {
			return Mac.getInstance(macAlgorithm);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalArgumentException("Invalid MAC algorithm.", e);
		}
	}

	/**
	 * Creates a MAC initialized with the given key.
	 *
	 * @param key Key to use in keyed MAC
	 * @return New Mac instance
	 */
	public Mac keyed(SecretKey key) {
		Mac mac = createMac();
		try {
			mac.init(key);
			return mac;
		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException("Invalid key.", e);
		}
	}

}
