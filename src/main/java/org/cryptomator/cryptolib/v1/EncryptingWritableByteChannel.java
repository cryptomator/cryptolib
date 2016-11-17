/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v1;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.WritableByteChannel;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.common.ByteBuffers;

public class EncryptingWritableByteChannel implements WritableByteChannel {

	private final WritableByteChannel delegate;
	private final Cryptor cryptor;
	private final FileHeader header;
	private final ByteBuffer cleartextBuffer;
	long written = 0;
	long chunkNumber = 0;

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
	public void close() throws IOException {
		encryptAndflushBuffer();
		delegate.close();
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
