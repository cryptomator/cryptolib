/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v2;

import com.google.common.base.Preconditions;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;

import javax.security.auth.Destroyable;
import java.nio.ByteBuffer;

class FileHeaderImpl implements FileHeader, Destroyable {

	static final int NONCE_POS = 0;
	static final int NONCE_LEN = Constants.GCM_NONCE_SIZE;
	static final int PAYLOAD_POS = NONCE_POS + NONCE_LEN; // 12
	static final int PAYLOAD_LEN = Payload.SIZE;
	static final int TAG_POS = PAYLOAD_POS + PAYLOAD_LEN; // 52
	static final int TAG_LEN = Constants.GCM_TAG_SIZE;
	static final int SIZE = NONCE_LEN + PAYLOAD_LEN + TAG_LEN;

	private final byte[] nonce;
	private final Payload payload;

	FileHeaderImpl(byte[] nonce, Payload payload) {
		if (nonce.length != NONCE_LEN) {
			throw new IllegalArgumentException("Invalid nonce length. (was: " + nonce.length + ", required: " + NONCE_LEN + ")");
		}
		this.nonce = nonce;
		this.payload = payload;
	}

	static FileHeaderImpl cast(FileHeader header) {
		if (header instanceof FileHeaderImpl) {
			return (FileHeaderImpl) header;
		} else {
			throw new IllegalArgumentException("Unsupported header type " + header.getClass());
		}
	}

	public byte[] getNonce() {
		return nonce;
	}

	public Payload getPayload() {
		return payload;
	}

	@Override
	public long getReserved() {
		return payload.getReserved();
	}

	@Override
	public void setReserved(long reserved) {
		payload.setReserved(reserved);
	}

	@Override
	public boolean isDestroyed() {
		return payload.isDestroyed();
	}

	@Override
	public void destroy() {
		payload.destroy();
	}

	public static class Payload implements Destroyable {

		static final int REVERSED_LEN = Long.BYTES;
		static final int CONTENT_KEY_LEN = 32;
		static final int SIZE = REVERSED_LEN + CONTENT_KEY_LEN;

		private long reserved;
		private final DestroyableSecretKey contentKey;

		Payload(long reversed, byte[] contentKeyBytes) {
			Preconditions.checkArgument(contentKeyBytes.length == CONTENT_KEY_LEN, "Invalid key length. (was: " + contentKeyBytes.length + ", required: " + CONTENT_KEY_LEN + ")");
			this.reserved = reversed;
			this.contentKey = new DestroyableSecretKey(contentKeyBytes, Constants.CONTENT_ENC_ALG);
		}

		static Payload decode(ByteBuffer cleartextPayloadBuf) {
			Preconditions.checkArgument(cleartextPayloadBuf.remaining() == SIZE, "invalid payload buffer length");
			long reserved = cleartextPayloadBuf.getLong();
			byte[] contentKeyBytes = new byte[CONTENT_KEY_LEN];
			cleartextPayloadBuf.get(contentKeyBytes);
			return new Payload(reserved, contentKeyBytes);
		}

		ByteBuffer encode() {
			ByteBuffer buf = ByteBuffer.allocate(SIZE);
			buf.putLong(reserved);
			buf.put(contentKey.getEncoded());
			buf.flip();
			return buf;
		}

		private long getReserved() {
			return reserved;
		}

		private void setReserved(long reserved) {
			this.reserved = reserved;
		}

		DestroyableSecretKey getContentKey() {
			return contentKey;
		}

		@Override
		public boolean isDestroyed() {
			return contentKey.isDestroyed();
		}

		@Override
		public void destroy() {
			contentKey.destroy();
		}

	}

}
