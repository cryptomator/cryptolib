package org.cryptomator.cryptolib.io;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.security.SecureRandom;
import java.util.Objects;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.common.ByteBuffers;

public class EncryptingWritableByteChannel implements WritableByteChannel {

	private static final int GARBAGE_PATTERN_SIZE = 33;

	private final SeekableByteChannel delegate;
	private final Cryptor cryptor;
	private final SecureRandom random;
	private final double preferredPaddingRatio;
	private final int minLength;
	private final int maxLength;
	private final ByteBuffer garbage;
	private final FileHeader header;
	private final ByteBuffer cleartextBuffer;
	long written = 0;
	long chunkNumber = 0;

	public EncryptingWritableByteChannel(SeekableByteChannel destination, Cryptor cryptor) {
		this(destination, cryptor, null, 0.0, 0, 0);
	}

	public EncryptingWritableByteChannel(SeekableByteChannel destination, Cryptor cryptor, SecureRandom random, double preferredBloatFactor, int minLength, int maxLength) {
		this.delegate = destination;
		this.cryptor = cryptor;
		this.random = random;
		this.preferredPaddingRatio = preferredBloatFactor;
		this.minLength = minLength;
		this.maxLength = maxLength;
		this.garbage = ByteBuffer.allocate(cryptor.fileContentCryptor().cleartextChunkSize());
		this.header = cryptor.fileHeaderCryptor().create();
		this.cleartextBuffer = ByteBuffer.allocate(cryptor.fileContentCryptor().cleartextChunkSize());
		if (maxLength > 0) {
			byte[] garbagePattern = new byte[GARBAGE_PATTERN_SIZE];
			Objects.requireNonNull(random).nextBytes(garbagePattern);
			fillArray(garbage.array(), garbagePattern);
		}
	}

	private static void fillArray(byte[] array, byte[] pattern) {
		for (int i = 0; i < array.length; i += pattern.length) {
			System.arraycopy(pattern, 0, array, i, Math.min(pattern.length, array.length - i));
		}
	}

	@Override
	public boolean isOpen() {
		return delegate.isOpen();
	}

	@Override
	public void close() throws IOException {
		header.setFilesize(written);
		if (written == 0) {
			delegate.write(cryptor.fileHeaderCryptor().encryptHeader(header));
			writePadding();
		} else {
			writePadding();
			delegate.position(0);
			delegate.write(cryptor.fileHeaderCryptor().encryptHeader(header));
		}
		delegate.close();
	}

	private void writePadding() throws IOException {
		if (maxLength > 0) {
			int maxPaddingLength = (int) Math.min(Math.max(written * preferredPaddingRatio, minLength), maxLength);
			int remainingPaddingLength = random.nextInt(maxPaddingLength);
			while (remainingPaddingLength > 0) {
				garbage.limit(Math.min(remainingPaddingLength, garbage.limit()));
				remainingPaddingLength -= ByteBuffers.copy(garbage, cleartextBuffer);
				encryptAndflushBuffer();
			}
		}
		encryptAndflushBuffer();
	}

	@Override
	public int write(ByteBuffer src) throws IOException {
		if (written == 0) {
			delegate.write(cryptor.fileHeaderCryptor().encryptHeader(header));
		}
		int result = 0;
		while (src.hasRemaining()) {
			result += ByteBuffers.copy(src, cleartextBuffer);
			if (!cleartextBuffer.hasRemaining()) {
				encryptAndflushBuffer();
			}
		}
		written += result;
		return result;
	}

	private void encryptAndflushBuffer() throws IOException {
		cleartextBuffer.flip();
		if (cleartextBuffer.hasRemaining()) {
			ByteBuffer ciphertextBuffer = cryptor.fileContentCryptor().encryptChunk(cleartextBuffer, chunkNumber++, header);
			delegate.write(ciphertextBuffer);
		}
		cleartextBuffer.clear();
	}

}
