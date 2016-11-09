/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.common;

import java.security.SecureRandom;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

public class ReseedingSecureRandomTest {

	private SecureRandom seeder, csprng;

	@Before
	public void setup() {
		seeder = Mockito.mock(SecureRandom.class);
		csprng = Mockito.mock(SecureRandom.class);
		Mockito.when(seeder.generateSeed(Mockito.anyInt())).then(new Answer<byte[]>() {
			@Override
			public byte[] answer(InvocationOnMock invocation) throws Throwable {
				int num = invocation.getArgumentAt(0, Integer.class);
				return new byte[num];
			}
		});

	}

	@Test
	public void testReseedAfterLimitReached() {
		SecureRandom rand = new ReseedingSecureRandom(seeder, csprng, 10, 3);
		Mockito.verify(seeder, Mockito.never()).generateSeed(3);
		rand.nextBytes(new byte[4]);
		Mockito.verify(seeder, Mockito.times(1)).generateSeed(3);
		rand.nextBytes(new byte[4]);
		Mockito.verify(seeder, Mockito.times(1)).generateSeed(3);
		rand.nextBytes(new byte[4]);
		Mockito.verify(seeder, Mockito.times(2)).generateSeed(3);
	}

}
