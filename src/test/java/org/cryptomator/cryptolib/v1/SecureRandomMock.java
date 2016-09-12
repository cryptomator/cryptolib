/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v1;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

class SecureRandomMock extends SecureRandom {

	private static final ByteFiller NULL_FILLER = new ByteFiller() {

		@Override
		public void fill(byte[] bytes) {
			Arrays.fill(bytes, (byte) 0x00);
		}

	};
	public static final SecureRandomMock NULL_RANDOM = new SecureRandomMock(NULL_FILLER);
	private static final ByteFiller PRNG_FILLER = new ByteFiller() {

		private final Random random = new Random();

		@Override
		public void fill(byte[] bytes) {
			random.nextBytes(bytes);
		}

	};
	public static final SecureRandomMock PRNG_RANDOM = new SecureRandomMock(PRNG_FILLER);

	private final ByteFiller byteFiller;

	public SecureRandomMock(ByteFiller byteFiller) {
		this.byteFiller = byteFiller;
	}

	@Override
	public void nextBytes(byte[] bytes) {
		byteFiller.fill(bytes);

	}

	private static interface ByteFiller {
		void fill(byte[] bytes);
	}

}
