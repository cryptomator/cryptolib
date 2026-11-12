package org.cryptomator.cryptolib.cvf8;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.CipherCombo;
import org.cryptomator.cryptolib.api.CvfMasterkey;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;
import org.cryptomator.cryptolib.common.SecureRandomMock;
import org.cryptomator.cryptolib.internal.FileHeaderParts;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

/**
 * Needs to be compiled via maven as the JMH annotation processor needs to do stuff...
 */
@State(Scope.Thread)
@Warmup(iterations = 3, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 2, time = 1, timeUnit = TimeUnit.SECONDS)
@BenchmarkMode(value = {Mode.AverageTime})
@OutputTimeUnit(TimeUnit.MICROSECONDS)
public class ContentCodecBenchmark {

	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.PRNG_RANDOM;
	private static final DestroyableSecretKey FILE_KEY = new DestroyableSecretKey(new byte[32], "AES");

	@Param({"SIV_CTRMAC", "SIV_GCM"})
	public String combo;

	private Cvf8ContentCodec codec;
	private byte[] headerNonce;
	private ByteBuffer cleartextChunk;
	private ByteBuffer ciphertextChunk;
	private ByteBuffer encryptedHeader;
	private long chunkIndex;

	@Setup(Level.Trial)
	public void prepareData() {
		CvfMasterkey masterkey = new CvfMasterkey(new byte[64]);
		codec = CipherCombo.valueOf(combo) == CipherCombo.SIV_CTRMAC ? new CtrMacCodec(masterkey, RANDOM_MOCK) : new GcmCodec(masterkey, RANDOM_MOCK);
		headerNonce = new byte[16];
		cleartextChunk = ByteBuffer.allocate(codec.layout().cleartextChunkSize());
		ciphertextChunk = ByteBuffer.allocate(codec.layout().ciphertextChunkSize());
		codec.encryptChunk(headerNonce, FILE_KEY, cleartextChunk, ciphertextChunk, 0L);
		ciphertextChunk.flip();
		encryptedHeader = codec.createHeader().encrypted();
	}

	@Setup(Level.Invocation)
	public void shuffleData() {
		chunkIndex = RANDOM_MOCK.nextLong() & Long.MAX_VALUE;
		cleartextChunk.rewind();
		ciphertextChunk.rewind();
		RANDOM_MOCK.nextBytes(cleartextChunk.array());
	}

	@Benchmark
	public void benchmarkChunkEncryption() {
		codec.encryptChunk(headerNonce, FILE_KEY, cleartextChunk, ciphertextChunk, chunkIndex);
	}

	@Benchmark
	public void benchmarkChunkDecryption() throws AuthenticationFailedException {
		codec.decryptChunk(headerNonce, FILE_KEY, ciphertextChunk, cleartextChunk, 0L);
	}

	@Benchmark
	public FileHeaderParts benchmarkHeaderCreation() {
		return codec.createHeader();
	}

	@Benchmark
	public FileHeaderParts benchmarkHeaderDecryption() throws AuthenticationFailedException {
		encryptedHeader.rewind();
		return codec.decryptHeader(encryptedHeader);
	}

}
