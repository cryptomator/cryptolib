package org.cryptomator.cryptolib.common;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
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
import org.openjdk.jmh.infra.Blackhole;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.Random;
import java.util.concurrent.TimeUnit;

@State(Scope.Thread)
@Warmup(iterations = 2)
@Measurement(iterations = 2)
@BenchmarkMode(value = {Mode.AverageTime})
@OutputTimeUnit(TimeUnit.MICROSECONDS)
public class PooledSuppliersBenchmarkTest {

	private static final Random RNG = new Random(42);
	private static final CipherSupplier CIPHER_SUPPLIER = CipherSupplier.AES_GCM;
	private static final MessageDigestSupplier MD_SUPPLIER = MessageDigestSupplier.SHA256;
	private static final MacSupplier MAC_SUPPLIER = MacSupplier.HMAC_SHA256;
	private SecretKey key;
	private GCMParameterSpec gcmParams;

	@Disabled("only on demand")
	@Test
	public void runBenchmarks() throws RunnerException {
		Options opt = new OptionsBuilder() //
				.include(getClass().getName()) //
				.threads(2).forks(1) //
				.shouldFailOnError(true).shouldDoGC(true) //
				.build();
		new Runner(opt).run();
	}

	@Setup(Level.Invocation)
	public void shuffleData() {
		byte[] bytes = new byte[28];
		RNG.nextBytes(bytes);
		this.key = new SecretKeySpec(bytes, 0, 16, "AES");
		this.gcmParams = new GCMParameterSpec(128, bytes, 16, 12);
	}

	@Benchmark
	public void createCipher(Blackhole blackHole) {
		blackHole.consume(CIPHER_SUPPLIER.forEncryption(key, gcmParams));
	}

	@Benchmark
	public void recycleCipher(Blackhole blackHole) {
		try (ObjectPool.Lease<Cipher> lease = CIPHER_SUPPLIER.encryptionCipher(key, gcmParams)) {
			blackHole.consume(lease.get());
		}
	}

	@Benchmark
	public void createMac(Blackhole blackHole) {
		blackHole.consume(MAC_SUPPLIER.withKey(key));
	}

	@Benchmark
	public void recycleMac(Blackhole blackHole) {
		try (ObjectPool.Lease<Mac> lease = MAC_SUPPLIER.keyed(key)) {
			blackHole.consume(lease.get());
		}
	}

	@Benchmark
	public void createMd(Blackhole blackHole) {
		blackHole.consume(MD_SUPPLIER.get());
	}

	@Benchmark
	public void recycleMd(Blackhole blackHole) {
		try (ObjectPool.Lease<MessageDigest> lease = MD_SUPPLIER.instance()) {
			blackHole.consume(lease.get());
		}
	}

}
