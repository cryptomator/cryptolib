/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;
import java.util.function.Consumer;

// TODO make class package-private
public class SecureRandomMock extends SecureRandom {

	private static final Consumer<byte[]> NULL_FILLER = new Consumer<byte[]>() {

		@Override
		public void accept(byte[] bytes) {
			Arrays.fill(bytes, (byte) 0x00);
		}

	};
	public static final SecureRandomMock NULL_RANDOM = new SecureRandomMock(NULL_FILLER);
	private static final Consumer<byte[]> PRNG_FILLER = new Consumer<byte[]>() {

		private final Random random = new Random();

		@Override
		public void accept(byte[] bytes) {
			random.nextBytes(bytes);
		}

	};
	public static final SecureRandomMock PRNG_RANDOM = new SecureRandomMock(PRNG_FILLER);

	private final Consumer<byte[]> byteFiller;

	public SecureRandomMock(Consumer<byte[]> byteFiller) {
		this.byteFiller = byteFiller;
	}

	@Override
	public void nextBytes(byte[] bytes) {
		byteFiller.accept(bytes);

	}

}
