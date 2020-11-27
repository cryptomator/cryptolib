/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v2;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.common.SecureRandomMock;
import org.mockito.Mockito;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

/**
 * Needs to be compiled via maven as the JMH annotation processor needs to do stuff...
 */
@State(Scope.Thread)
@Warmup(iterations = 3, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 2, time = 1, timeUnit = TimeUnit.SECONDS)
@BenchmarkMode(value = {Mode.AverageTime})
@OutputTimeUnit(TimeUnit.MICROSECONDS)
public class FileHeaderCryptorBenchmark {

	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.PRNG_RANDOM;
	private static final SecretKey ENC_KEY = new SecretKeySpec(new byte[16], "AES");
	private static final FileHeaderCryptorImpl HEADER_CRYPTOR = new FileHeaderCryptorImpl(ENC_KEY, RANDOM_MOCK);

	private ByteBuffer validHeaderCiphertextBuf;
	private FileHeader header;

	@Setup(Level.Iteration)
	public void prepareData() {
		validHeaderCiphertextBuf = HEADER_CRYPTOR.encryptHeader(HEADER_CRYPTOR.create());
	}

	@Setup(Level.Invocation)
	public void shuffleData() {
		header = HEADER_CRYPTOR.create();
	}

	@Benchmark
	public void benchmarkEncryption() {
		HEADER_CRYPTOR.encryptHeader(header);
	}

	@Benchmark
	public void benchmarkDecryption() throws AuthenticationFailedException {
		HEADER_CRYPTOR.decryptHeader(validHeaderCiphertextBuf);
	}

}
