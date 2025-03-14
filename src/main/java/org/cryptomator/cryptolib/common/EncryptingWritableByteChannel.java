package org.cryptomator.cryptolib.common;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileHeader;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.WritableByteChannel;

public class EncryptingWritableByteChannel implements WritableByteChannel {

	private final WritableByteChannel delegate;
	private final Cryptor cryptor;
	private final FileHeader header;
	private final ByteBuffer cleartextBuffer;

	private boolean firstWrite = true;
	private long chunkNumber = 0;

	public EncryptingWritableByteChannel(WritableByteChannel destination, Cryptor cryptor) {
		this.delegate = destination;
		this.cryptor = cryptor;
		this.header = cryptor.fileHeaderCryptor().create();
		this.cleartextBuffer = ByteBuffer.allocate(cryptor.fileContentCryptor().cleartextChunkSize());
	}

	@Override
	public boolean isOpen() {
		return delegate.isOpen();
	}

	@Override
	public synchronized void close() throws IOException {
		writeHeaderOnFirstWrite();
		encryptAndFlushBuffer();
		delegate.close();
	}

	@Override
	public synchronized int write(ByteBuffer src) throws IOException {
		writeHeaderOnFirstWrite();
		int result = 0;
		while (src.hasRemaining()) {
			result += ByteBuffers.copy(src, cleartextBuffer);
			if (!cleartextBuffer.hasRemaining()) {
				encryptAndFlushBuffer();
			}
		}
		return result;
	}

	private void writeHeaderOnFirstWrite() throws IOException {
		if (firstWrite) {
			delegate.write(cryptor.fileHeaderCryptor().encryptHeader(header));
		}
		firstWrite = false;
	}

	private void encryptAndFlushBuffer() throws IOException {
		cleartextBuffer.flip();
		ByteBuffer ciphertextBuffer = cryptor.fileContentCryptor().encryptChunk(cleartextBuffer, chunkNumber++, header);
		delegate.write(ciphertextBuffer);
		cleartextBuffer.clear();
	}

}
