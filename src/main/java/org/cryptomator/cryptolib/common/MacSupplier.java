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

public final class MacSupplier {

	public static final MacSupplier HMAC_SHA256 = new MacSupplier("HmacSHA256");

	private final String macAlgorithm;
	private final ObjectPool<Mac> macPool;

	public MacSupplier(String macAlgorithm) {
		this.macAlgorithm = macAlgorithm;
		this.macPool = new ObjectPool<>(this::createMac);
		try (ObjectPool.Lease<Mac> lease = macPool.get()) {
			lease.get(); // eagerly initialize to provoke exceptions
		}
	}

	private Mac createMac() {
		try {
			return Mac.getInstance(macAlgorithm);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalArgumentException("Invalid MAC algorithm.", e);
		}
	}

	/**
	 * Leases a reusable MAC object initialized with the given key.
	 *
	 * @param key Key to use in keyed MAC
	 * @return A lease supplying a refurbished MAC
	 */
	public ObjectPool.Lease<Mac> keyed(SecretKey key) {
		ObjectPool.Lease<Mac> lease = macPool.get();
		init(lease.get(), key);
		return lease;
	}

	/**
	 * Creates a new MAC
	 *
	 * @param key Key to use in keyed MAC
	 * @return New Mac instance
	 * @deprecated Use {@link #keyed(SecretKey)} instead
	 */
	@Deprecated
	public Mac withKey(SecretKey key) {
		final Mac mac = createMac();
		init(mac, key);
		return mac;
	}

	private void init(Mac mac, SecretKey key) {
		try {
			mac.init(key);
		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException("Invalid key.", e);
		}
	}

}