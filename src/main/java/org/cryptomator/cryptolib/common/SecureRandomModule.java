/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.common;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.inject.Qualifier;

import dagger.Module;
import dagger.Provides;

@Module
public class SecureRandomModule {

	private final SecureRandom seeder;

	/**
	 * Recommended invocation for Java 8 is:
	 * 
	 * <pre>
	 * new SecureRandomModule(SecureRandom.getInstanceStrong());
	 * </pre>
	 * 
	 * @param seeder A cryptographically strong SecureRandom instance, using real system entropy if possible.
	 */
	public SecureRandomModule(SecureRandom seeder) {
		this.seeder = seeder;
	}

	@Provides
	@NativeSecureRandom
	public SecureRandom provideNativeSecureRandom() {
		return this.seeder;
	}

	@Provides
	@FastSecureRandom
	public SecureRandom provideFastSecureRandom(@NativeSecureRandom SecureRandom seeder) {
		try {
			// NIST SP 800-90A Rev 1 (http://dx.doi.org/10.6028/NIST.SP.800-90Ar1) suggests 440 seed bits for up to 2^48 bytes between reseeds for SHA1/SHA2 PRNGs:
			return new ReseedingSecureRandom(seeder, SecureRandom.getInstance("SHA1PRNG"), 1 << 30, 55);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("SHA1PRNG must exist in every Java platform.", e);
		}
	}

	/**
	 * Marks the original, possibly slow, {@link SecureRandom} used to seed and reseed the fast CSPRNG qualified by {@link FastSecureRandom}.
	 */
	@Qualifier
	@Documented
	@Retention(RetentionPolicy.RUNTIME)
	public @interface NativeSecureRandom {
	}

	/**
	 * Marks a relatively fast CSPRNG instance, which is a periodically reseeding CSPRNG using usually slower native {@link SecureRandom} qualified by {@link NativeSecureRandom}.
	 */
	@Qualifier
	@Documented
	@Retention(RetentionPolicy.RUNTIME)
	public @interface FastSecureRandom {
	}

}
