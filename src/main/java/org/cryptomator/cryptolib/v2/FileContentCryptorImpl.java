/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v2;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.FileContentCryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.common.CipherSupplier;
import org.cryptomator.cryptolib.common.MacSupplier;

import static org.cryptomator.cryptolib.v2.Constants.CHUNK_SIZE;
import static org.cryptomator.cryptolib.v2.Constants.GCM_TAG_SIZE;
import static org.cryptomator.cryptolib.v2.Constants.GCM_NONCE_SIZE;
import static org.cryptomator.cryptolib.v2.Constants.PAYLOAD_SIZE;

class FileContentCryptorImpl implements FileContentCryptor {

	private final SecureRandom random;

	FileContentCryptorImpl(SecureRandom random) {
		this.random = random;
	}

	@Override
	public int cleartextChunkSize() {
		return PAYLOAD_SIZE;
	}

	@Override
	public int ciphertextChunkSize() {
		return CHUNK_SIZE;
	}

	@Override
	public ByteBuffer encryptChunk(ByteBuffer cleartextChunk, long chunkNumber, FileHeader header) {
		if (cleartextChunk.remaining() == 0 || cleartextChunk.remaining() > PAYLOAD_SIZE) {
			throw new IllegalArgumentException("Invalid chunk");
		}
		FileHeaderImpl headerImpl = FileHeaderImpl.cast(header);
		return encryptChunk(cleartextChunk.asReadOnlyBuffer(), chunkNumber, headerImpl.getNonce(), headerImpl.getPayload().getContentKey());
	}

	@Override
	public ByteBuffer decryptChunk(ByteBuffer ciphertextChunk, long chunkNumber, FileHeader header, boolean authenticate) throws AuthenticationFailedException {
		if (ciphertextChunk.remaining() < GCM_NONCE_SIZE + GCM_TAG_SIZE || ciphertextChunk.remaining() > CHUNK_SIZE) {
			throw new IllegalArgumentException("Invalid chunk size: " + ciphertextChunk.remaining() + ", expected range [" + (GCM_NONCE_SIZE + GCM_TAG_SIZE) + ", " + CHUNK_SIZE + "]");
		}
		if (!authenticate) {
			throw new UnsupportedOperationException("authenticate can not be false");
		}
		FileHeaderImpl headerImpl = FileHeaderImpl.cast(header);
		return decryptChunk(ciphertextChunk.asReadOnlyBuffer(), chunkNumber, headerImpl.getNonce(), headerImpl.getPayload().getContentKey());
	}

	// visible for testing
	ByteBuffer encryptChunk(ByteBuffer cleartextChunk, long chunkNumber, byte[] headerNonce, SecretKey fileKey) {
		try {
			// nonce:
			byte[] nonce = new byte[GCM_NONCE_SIZE];
			random.nextBytes(nonce);

			// payload:
			final Cipher cipher = CipherSupplier.AES_GCM.forEncryption(fileKey, new GCMParameterSpec(GCM_TAG_SIZE * Byte.SIZE, nonce));
			final byte[] chunkNumberBigEndian = longToBigEndianByteArray(chunkNumber);
			cipher.updateAAD(chunkNumberBigEndian);
			cipher.updateAAD(headerNonce);
			final ByteBuffer outBuf = ByteBuffer.allocate(GCM_NONCE_SIZE + cipher.getOutputSize(cleartextChunk.remaining()));
			outBuf.put(nonce);
			int bytesEncrypted = cipher.doFinal(cleartextChunk, outBuf);

			// flip and return:
			outBuf.flip();
			return outBuf;
		} catch (ShortBufferException e) {
			throw new IllegalStateException("Buffer allocated for reported output size apparently not big enough.", e);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new IllegalStateException("Unexpected exception during GCM encryption.", e);
		}
	}

	// visible for testing
	ByteBuffer decryptChunk(ByteBuffer ciphertextChunk, long chunkNumber, byte[] headerNonce, SecretKey fileKey) {
		assert ciphertextChunk.remaining() >= GCM_NONCE_SIZE + GCM_TAG_SIZE;

		try {
			// nonce:
			final byte[] nonce = new byte[GCM_NONCE_SIZE];
			final ByteBuffer chunkNonceBuf = ciphertextChunk.asReadOnlyBuffer();
			chunkNonceBuf.position(0).limit(GCM_NONCE_SIZE);
			chunkNonceBuf.get(nonce);

			// payload:
			final ByteBuffer payloadBuf = ciphertextChunk.asReadOnlyBuffer();
			payloadBuf.position(GCM_NONCE_SIZE);
			assert payloadBuf.remaining() >= GCM_TAG_SIZE;

			// payload:
			final Cipher cipher = CipherSupplier.AES_GCM.forDecryption(fileKey, new GCMParameterSpec(GCM_TAG_SIZE * Byte.SIZE, nonce));
			final byte[] chunkNumberBigEndian = longToBigEndianByteArray(chunkNumber);
			cipher.updateAAD(chunkNumberBigEndian);
			cipher.updateAAD(headerNonce);
			final ByteBuffer outBuf = ByteBuffer.allocate(cipher.getOutputSize(payloadBuf.remaining()));
			cipher.doFinal(payloadBuf, outBuf);

			// flip and return:
			outBuf.flip();
			return outBuf;
		} catch (AEADBadTagException e) {
			throw new AuthenticationFailedException("Content tag mismatch.", e);
		} catch (ShortBufferException e) {
			throw new IllegalStateException("Buffer allocated for reported output size apparently not big enough.", e);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new IllegalStateException("Unexpected exception during GCM decryption.", e);
		}
	}

	private byte[] longToBigEndianByteArray(long n) {
		return ByteBuffer.allocate(Long.SIZE / Byte.SIZE).order(ByteOrder.BIG_ENDIAN).putLong(n).array();
	}

}
