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

	private final String digestAlgorithm;
	private final ThreadLocal<MessageDigest> threadLocal;

	public MessageDigestSupplier(String digestAlgorithm) {
		this.digestAlgorithm = digestAlgorithm;
		this.threadLocal = new Provider();
	}

	private class Provider extends ThreadLocal<MessageDigest> {
		@Override
		protected MessageDigest initialValue() {
			try {
				return MessageDigest.getInstance(digestAlgorithm);
			} catch (NoSuchAlgorithmException e) {
				throw new IllegalArgumentException("Invalid digest algorithm.", e);
			}
		}
	}

	public MessageDigest get() {
		final MessageDigest result = threadLocal.get();
		result.reset();
		return result;
	}

}