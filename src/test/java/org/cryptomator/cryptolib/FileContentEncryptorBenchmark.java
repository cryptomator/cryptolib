/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib;

import java.io.IOException;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.io.input.NullInputStream;
import org.apache.commons.io.output.NullOutputStream;
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
@Warmup(iterations = 2)
@Measurement(iterations = 2)
@BenchmarkMode(value = {Mode.SingleShotTime})
@OutputTimeUnit(TimeUnit.MILLISECONDS)
public class FileContentEncryptorBenchmark {

	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.PRNG_RANDOM;
	private static final SecretKey MAC_KEY = new SecretKeySpec(new byte[16], "HmacSHA256");
	private FileHeader header;

	@Setup(Level.Iteration)
	public void shuffleData() {
		header = FileHeaders.create(RANDOM_MOCK);
	}

	@Benchmark
	public void benchmark100MegabytesEncryption() throws IOException {
		ReadableByteChannel cleartextIn = Channels.newChannel(new NullInputStream(100l * 1024 * 1024));
		WritableByteChannel ciphertextOut = Channels.newChannel(new NullOutputStream());
		new FileContentEncryptor(header, MAC_KEY, RANDOM_MOCK).encrypt(cleartextIn, ciphertextOut, 0);
	}

	@Benchmark
	public void benchmark10MegabytesEncryption() throws IOException {
		ReadableByteChannel cleartextIn = Channels.newChannel(new NullInputStream(10l * 1024 * 1024));
		WritableByteChannel ciphertextOut = Channels.newChannel(new NullOutputStream());
		new FileContentEncryptor(header, MAC_KEY, RANDOM_MOCK).encrypt(cleartextIn, ciphertextOut, 0);
	}

	@Benchmark
	public void benchmark1MegabytesEncryption() throws IOException {
		ReadableByteChannel cleartextIn = Channels.newChannel(new NullInputStream(1l * 1024 * 1024));
		WritableByteChannel ciphertextOut = Channels.newChannel(new NullOutputStream());
		new FileContentEncryptor(header, MAC_KEY, RANDOM_MOCK).encrypt(cleartextIn, ciphertextOut, 0);
	}

}
