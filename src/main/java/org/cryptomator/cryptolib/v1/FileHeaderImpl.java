/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v1;

import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.Destroyable;

import org.cryptomator.cryptolib.api.FileHeader;

class FileHeaderImpl implements FileHeader, Destroyable {

	static final int NONCE_POS = 0;
	static final int NONCE_LEN = 16;
	static final int PAYLOAD_POS = 16;
	static final int PAYLOAD_LEN = Payload.SIZE;
	static final int MAC_POS = 56;
	static final int MAC_LEN = 32;
	static final int SIZE = NONCE_LEN + PAYLOAD_LEN + MAC_LEN;

	private final byte[] nonce;
	private final Payload payload;

	FileHeaderImpl(byte[] nonce, byte[] contentKey) {
		if (nonce.length != NONCE_LEN) {
			throw new IllegalArgumentException("Invalid nonce length. (was: " + nonce.length + ", required: " + NONCE_LEN + ")");
		}
		this.nonce = nonce;
		this.payload = new Payload(contentKey);
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
	public long getFilesize() {
		return payload.getFilesize();
	}

	@Override
	public void setFilesize(long filesize) {
		payload.setFilesize(filesize);
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

		static final int FILESIZE_POS = 0;
		static final int FILESIZE_LEN = 8;
		static final int CONTENT_KEY_POS = 8;
		static final int CONTENT_KEY_LEN = 32;
		static final int SIZE = FILESIZE_LEN + CONTENT_KEY_LEN;
		private static final byte[] EMPTY_CONTENT_KEY = new byte[CONTENT_KEY_LEN];

		private long filesize = -1L;
		private final byte[] contentKeyBytes;
		private final SecretKey contentKey;

		private Payload(byte[] contentKeyBytes) {
			if (contentKeyBytes.length != CONTENT_KEY_LEN) {
				throw new IllegalArgumentException("Invalid key length. (was: " + contentKeyBytes.length + ", required: " + CONTENT_KEY_LEN + ")");
			}
			this.contentKeyBytes = contentKeyBytes;
			this.contentKey = new SecretKeySpec(contentKeyBytes, Constants.ENC_ALG);
		}

		private long getFilesize() {
			return filesize;
		}

		private void setFilesize(long filesize) {
			this.filesize = filesize;
		}

		SecretKey getContentKey() {
			return contentKey;
		}

		byte[] getContentKeyBytes() {
			return contentKeyBytes;
		}

		@Override
		public boolean isDestroyed() {
			return Arrays.equals(contentKeyBytes, EMPTY_CONTENT_KEY);
		}

		@Override
		public void destroy() {
			Arrays.fill(contentKeyBytes, (byte) 0x00);
		}

	}

}
