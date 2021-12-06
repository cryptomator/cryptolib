/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.common;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public final class MessageDigestSupplier {

	public static final MessageDigestSupplier SHA1 = new MessageDigestSupplier("SHA-1");
	public static final MessageDigestSupplier SHA256 = new MessageDigestSupplier("SHA-256");

	private final String digestAlgorithm;
	private final ObjectPool<MessageDigest> mdPool;

	public MessageDigestSupplier(String digestAlgorithm) {
		this.digestAlgorithm = digestAlgorithm;
		this.mdPool = new ObjectPool<>(this::createMessageDigest);
		try (ObjectPool.Lease<MessageDigest> lease = mdPool.get()) {
			lease.get(); // eagerly initialize to provoke exceptions
		}
	}

	private MessageDigest createMessageDigest() {
		try {
			return MessageDigest.getInstance(digestAlgorithm);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalArgumentException("Invalid digest algorithm.", e);
		}
	}

	/**
	 * Leases a reusable MessageDigest.
	 *
	 * @return A ReusableMessageDigest instance holding a refurbished MessageDigest
	 */
	public ObjectPool.Lease<MessageDigest> instance() {
		ObjectPool.Lease<MessageDigest> lease = mdPool.get();
		lease.get().reset();
		return lease;
	}

	/**
	 * Creates a new MessageDigest.
	 *
	 * @return New MessageDigest instance
	 * @deprecated Use {@link #instance()}
	 */
	@Deprecated
	public MessageDigest get() {
		final MessageDigest result = createMessageDigest();
		result.reset();
		return result;
	}

}