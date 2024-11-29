package org.cryptomator.cryptolib.v3;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.api.UVFMasterkey;
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
import java.util.Base64;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.TimeUnit;

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
	private static final Map<Integer, byte[]> SEEDS = Collections.singletonMap(-1540072521, Base64.getDecoder().decode("fP4V4oAjsUw5DqackAvLzA0oP1kAQZ0f5YFZQviXSuU="));
	private static final byte[] KDF_SALT =  Base64.getDecoder().decode("HE4OP+2vyfLLURicF1XmdIIsWv0Zs6MobLKROUIEhQY=");
	private static final UVFMasterkey MASTERKEY = new UVFMasterkey(SEEDS, KDF_SALT, -1540072521, -1540072521);
	private static final FileHeaderCryptorImpl HEADER_CRYPTOR = new FileHeaderCryptorImpl(MASTERKEY, RANDOM_MOCK);

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
