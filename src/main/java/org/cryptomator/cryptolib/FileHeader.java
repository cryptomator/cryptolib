/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib;

import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.Destroyable;

/**
 * Contains file header data.
 * Use {@link FileHeaders} for construction.
 */
class FileHeader implements Destroyable {

	static final int NONCE_POS = 0;
	static final int NONCE_LEN = 16;
	static final int PAYLOAD_POS = 16;
	static final int PAYLOAD_LEN = Payload.SIZE;
	static final int MAC_POS = 56;
	static final int MAC_LEN = 32;
	static final int SIZE = NONCE_LEN + PAYLOAD_LEN + MAC_LEN;

	private final byte[] nonce;
	private final Payload payload;

	FileHeader(byte[] nonce, byte[] contentKey) {
		if (nonce.length != NONCE_LEN) {
			throw new IllegalArgumentException("Invalid nonce length. (was: " + nonce.length + ", required: " + NONCE_LEN + ")");
		}
		this.nonce = nonce;
		this.payload = new Payload(contentKey);
	}

	public byte[] getNonce() {
		return nonce;
	}

	public Payload getPayload() {
		return payload;
	}

	@Override
	public void destroy() {
		payload.destroy();
	}

	public static class Payload implements Destroyable {

		static final int FILESIZE_POS = 0;
		static final int FILESIZE_LEN = 8;
		static final int CONTENT_KEY_POS = 8;
		static final int CONTENT_KEY_LEN = 32;
		static final int SIZE = FILESIZE_LEN + CONTENT_KEY_LEN;

		private long filesize;
		private final byte[] contentKeyBytes;
		private final SecretKey contentKey;

		private Payload(byte[] contentKeyBytes) {
			if (contentKeyBytes.length != CONTENT_KEY_LEN) {
				throw new IllegalArgumentException("Invalid key length. (was: " + contentKeyBytes.length + ", required: " + CONTENT_KEY_LEN + ")");
			}
			this.contentKeyBytes = contentKeyBytes;
			this.contentKey = new SecretKeySpec(contentKeyBytes, Constants.ENC_ALG);
		}

		public long getFilesize() {
			return filesize;
		}

		public void setFilesize(long filesize) {
			this.filesize = filesize;
		}

		public SecretKey getContentKey() {
			return contentKey;
		}

		public byte[] getContentKeyBytes() {
			return contentKeyBytes;
		}

		@Override
		public void destroy() {
			Arrays.fill(contentKeyBytes, (byte) 0x00);
		}

	}

}
