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

import javax.crypto.Mac;
import javax.crypto.SecretKey;

public final class MacSupplier {

	public static final MacSupplier HMAC_SHA256 = new MacSupplier("HmacSHA256");

	private final String macAlgorithm;
	private final ThreadLocal<Mac> threadLocal;

	public MacSupplier(String macAlgorithm) {
		this.macAlgorithm = macAlgorithm;
		this.threadLocal = new Provider();
	}

	private class Provider extends ThreadLocal<Mac> {
		@Override
		protected Mac initialValue() {
			try {
				return Mac.getInstance(macAlgorithm);
			} catch (NoSuchAlgorithmException e) {
				throw new IllegalArgumentException("Invalid MAC algorithm.", e);
			}
		}
	}

	public Mac withKey(SecretKey key) {
		try {
			final Mac mac = threadLocal.get();
			mac.init(key);
			return mac;
		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException("Invalid key.", e);
		}
	}

}