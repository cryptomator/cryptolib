/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.common;

import com.google.common.collect.Iterators;
import com.google.common.primitives.Bytes;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Random;

public class SecureRandomMock extends SecureRandom {

	private static final ByteFiller NULL_FILLER = bytes -> Arrays.fill(bytes, (byte) 0x00);
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

	public static SecureRandomMock cycle(byte... bytes) {
		return new SecureRandomMock(new CyclicByteFiller(bytes));
	}

	public interface ByteFiller {
		void fill(byte[] bytes);
	}

	private static class CyclicByteFiller implements ByteFiller {

		private final Iterator<Byte> source;

		CyclicByteFiller(byte... bytes) {
			source = Iterators.cycle(Bytes.asList(bytes));
		}

		@Override
		public void fill(byte[] bytes) {
			Arrays.fill(bytes, source.next());
		}

	}

}
