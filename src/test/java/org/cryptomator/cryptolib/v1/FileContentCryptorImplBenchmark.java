/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v1;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

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
public class FileContentCryptorImplBenchmark {

	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.PRNG_RANDOM;
	private static final SecretKey ENC_KEY = new SecretKeySpec(new byte[16], "AES");
	private static final SecretKey MAC_KEY = new SecretKeySpec(new byte[16], "HmacSHA256");
	private final byte[] headerNonce = new byte[Constants.NONCE_SIZE];
	private final ByteBuffer cleartextChunk = ByteBuffer.allocate(Constants.PAYLOAD_SIZE);
	private final ByteBuffer ciphertextChunk = ByteBuffer.allocate(Constants.CHUNK_SIZE);
	private final FileContentCryptorImpl fileContentCryptor = new FileContentCryptorImpl(MAC_KEY, RANDOM_MOCK);
	private long chunkNumber;

	@Setup(Level.Invocation)
	public void shuffleData() {
		chunkNumber = RANDOM_MOCK.nextLong();
		cleartextChunk.rewind();
		ciphertextChunk.rewind();
		RANDOM_MOCK.nextBytes(headerNonce);
		RANDOM_MOCK.nextBytes(cleartextChunk.array());
		RANDOM_MOCK.nextBytes(ciphertextChunk.array());
	}

	@Benchmark
	public void benchmarkEncryption() {
		fileContentCryptor.encryptChunk(cleartextChunk, chunkNumber, headerNonce, ENC_KEY);
	}

	@Benchmark
	public void benchmarkAuthentication() {
		fileContentCryptor.checkChunkMac(headerNonce, chunkNumber, ciphertextChunk);
	}

	@Benchmark
	public void benchmarkDecryption() {
		fileContentCryptor.decryptChunk(ciphertextChunk, ENC_KEY);
	}

}
