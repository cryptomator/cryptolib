/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.common;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.security.SecureRandom;

public class ReseedingSecureRandomTest {

	private SecureRandom seeder, csprng;

	@BeforeEach
	public void setup() {
		seeder = Mockito.mock(SecureRandom.class);
		csprng = Mockito.mock(SecureRandom.class);
		Mockito.when(seeder.generateSeed(Mockito.anyInt())).then(invocation ->  {
			int num = invocation.getArgument(0);
			return new byte[num];
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
