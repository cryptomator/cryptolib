package org.cryptomator.cryptolib.v3;

import org.cryptomator.cryptolib.api.UVFMasterkey;
import org.cryptomator.cryptolib.common.EncryptingWritableByteChannel;
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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.TimeUnit;

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
	private static final Map<Integer, byte[]> SEEDS = Collections.singletonMap(-1540072521, Base64.getDecoder().decode("fP4V4oAjsUw5DqackAvLzA0oP1kAQZ0f5YFZQviXSuU="));
	private static final byte[] KDF_SALT =  Base64.getDecoder().decode("HE4OP+2vyfLLURicF1XmdIIsWv0Zs6MobLKROUIEhQY=");
	private static final UVFMasterkey MASTERKEY = new UVFMasterkey(SEEDS, KDF_SALT, -1540072521, -1540072521);

	private CryptorImpl cryptor;

	@Setup(Level.Iteration)
	public void shuffleData() {
		cryptor = new CryptorImpl(MASTERKEY, RANDOM_MOCK);
	}

	@Benchmark
	public void benchmark100MegabytesEncryption() throws IOException {
		ByteBuffer megabyte = ByteBuffer.allocate(1 * 1024 * 1024);
		try (WritableByteChannel ch = new EncryptingWritableByteChannel(new NullSeekableByteChannel(), cryptor)) {
			for (int i = 0; i < 100; i++) {
				ch.write(megabyte);
				megabyte.clear();
			}
		}
	}

	@Benchmark
	public void benchmark10MegabytesEncryption() throws IOException {
		ByteBuffer megabyte = ByteBuffer.allocate(1 * 1024 * 1024);
		try (WritableByteChannel ch = new EncryptingWritableByteChannel(new NullSeekableByteChannel(), cryptor)) {
			for (int i = 0; i < 10; i++) {
				ch.write(megabyte);
				megabyte.clear();
			}
		}
	}

	@Benchmark
	public void benchmark1MegabytesEncryption() throws IOException {
		ByteBuffer megabyte = ByteBuffer.allocate(1 * 1024 * 1024);
		try (WritableByteChannel ch = new EncryptingWritableByteChannel(new NullSeekableByteChannel(), cryptor)) {
			ch.write(megabyte);
			megabyte.clear();
		}
	}

	private static class NullSeekableByteChannel implements SeekableByteChannel {

		boolean open;

		@Override
		public boolean isOpen() {
			return open;
		}

		@Override
		public void close() {
			open = false;
		}

		@Override
		public int read(ByteBuffer dst) {
			throw new UnsupportedOperationException();
		}

		@Override
		public int write(ByteBuffer src) {
			int delta = src.remaining();
			src.position(src.position() + delta);
			return delta;
		}

		@Override
		public long position() {
			return 0;
		}

		@Override
		public SeekableByteChannel position(long newPosition) {
			return this;
		}

		@Override
		public long size() {
			return 0;
		}

		@Override
		public SeekableByteChannel truncate(long size) {
			return this;
		}

	}

}
