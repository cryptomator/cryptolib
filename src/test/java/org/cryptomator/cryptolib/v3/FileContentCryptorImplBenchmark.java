package org.cryptomator.cryptolib.v3;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;
import org.cryptomator.cryptolib.common.SecureRandomMock;
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
public class FileContentCryptorImplBenchmark {

	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.PRNG_RANDOM;
	private static final DestroyableSecretKey ENC_KEY = new DestroyableSecretKey(new byte[16], "AES");
	private final byte[] headerNonce = new byte[FileHeaderImpl.NONCE_LEN];
	private final ByteBuffer cleartextChunk = ByteBuffer.allocate(Constants.PAYLOAD_SIZE);
	private final ByteBuffer ciphertextChunk = ByteBuffer.allocate(Constants.CHUNK_SIZE);
	private final FileContentCryptorImpl fileContentCryptor = new FileContentCryptorImpl(RANDOM_MOCK);
	private long chunkNumber;

	@Setup(Level.Trial)
	public void prepareData() {
		cleartextChunk.rewind();
		fileContentCryptor.encryptChunk(cleartextChunk, ciphertextChunk, 0l, new byte[12], ENC_KEY);
		ciphertextChunk.flip();
	}

	@Setup(Level.Invocation)
	public void shuffleData() {
		chunkNumber = RANDOM_MOCK.nextLong();
		cleartextChunk.rewind();
		ciphertextChunk.rewind();
		RANDOM_MOCK.nextBytes(headerNonce);
		RANDOM_MOCK.nextBytes(cleartextChunk.array());
	}

	@Benchmark
	public void benchmarkEncryption() {
		fileContentCryptor.encryptChunk(cleartextChunk, ciphertextChunk, chunkNumber, headerNonce, ENC_KEY);
	}

	@Benchmark
	public void benchmarkDecryption() throws AuthenticationFailedException {
		fileContentCryptor.decryptChunk(ciphertextChunk, cleartextChunk, 0l, new byte[12], ENC_KEY);
	}

}
