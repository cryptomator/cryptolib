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

/**
 * Creates {@link MessageDigest} instances for one algorithm, translating the checked JCA exception into an {@link IllegalArgumentException}.
 */
public final class MessageDigestSupplier {

	public static final MessageDigestSupplier SHA1 = new MessageDigestSupplier("SHA-1");
	public static final MessageDigestSupplier SHA256 = new MessageDigestSupplier("SHA-256");

	private final String digestAlgorithm;

	/**
	 * @param digestAlgorithm The JCA digest algorithm, e.g. {@code SHA-256}
	 * @throws IllegalArgumentException If no provider supports it
	 */
	public MessageDigestSupplier(String digestAlgorithm) {
		this.digestAlgorithm = digestAlgorithm;
		instance(); // eagerly initialize to provoke exceptions
	}

	/**
	 * @return New MessageDigest instance
	 */
	public MessageDigest instance() {
		try {
			return MessageDigest.getInstance(digestAlgorithm);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalArgumentException("Invalid digest algorithm.", e);
		}
	}

}
