package org.cryptomator.cryptolib.uvf;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;
import org.cryptomator.cryptolib.common.SecureRandomMock;
import org.cryptomator.cryptolib.internal.FileHeaderParts;
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
public class UvfContentCodecBenchmark {

	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.PRNG_RANDOM;
	private static final DestroyableSecretKey FILE_KEY = new DestroyableSecretKey(new byte[32], "AES");

	private UvfSeeds seeds;
	private UvfContentCodec codec;
	private final byte[] headerNonce = new byte[12];
	private final ByteBuffer cleartextChunk = ByteBuffer.allocate(Constants.PAYLOAD_SIZE);
	private final ByteBuffer ciphertextChunk = ByteBuffer.allocate(Constants.CHUNK_SIZE);
	private ByteBuffer encryptedHeader;
	private long chunkIndex;

	@Setup(Level.Trial)
	public void prepareData() {
		seeds = UvfSeeds.create(RANDOM_MOCK);
		codec = new UvfContentCodec(seeds, RANDOM_MOCK);
		codec.encryptChunk(headerNonce, FILE_KEY, cleartextChunk, ciphertextChunk, 0L);
		ciphertextChunk.flip();
		encryptedHeader = codec.createHeader(seeds.latestSeedId(), Constants.KDF_CONTEXT_FILE_HEADER).encrypted();
	}

	@Setup(Level.Invocation)
	public void shuffleData() {
		chunkIndex = RANDOM_MOCK.nextInt() & 0xFFFFFFFFL;
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
		return codec.createHeader(seeds.latestSeedId(), Constants.KDF_CONTEXT_FILE_HEADER);
	}

	@Benchmark
	public FileHeaderParts benchmarkHeaderDecryption() throws AuthenticationFailedException {
		encryptedHeader.rewind();
		return codec.decryptHeader(encryptedHeader, Constants.KDF_CONTEXT_FILE_HEADER);
	}

}
