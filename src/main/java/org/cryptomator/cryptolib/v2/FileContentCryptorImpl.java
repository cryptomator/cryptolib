/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v2;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.CryptoException;
import org.cryptomator.cryptolib.api.FileContentCryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.common.CipherSupplier;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;

import static org.cryptomator.cryptolib.v2.Constants.CHUNK_SIZE;
import static org.cryptomator.cryptolib.v2.Constants.GCM_NONCE_SIZE;
import static org.cryptomator.cryptolib.v2.Constants.GCM_TAG_SIZE;
import static org.cryptomator.cryptolib.v2.Constants.PAYLOAD_SIZE;

class FileContentCryptorImpl implements FileContentCryptor {

	private final SecureRandom random;

	FileContentCryptorImpl(SecureRandom random) {
		this.random = random;
	}

	@Override
	public boolean canSkipAuthentication() {
		return false;
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
		ByteBuffer ciphertextChunk = ByteBuffer.allocate(CHUNK_SIZE);
		encryptChunk(cleartextChunk, ciphertextChunk, chunkNumber, header);
		ciphertextChunk.flip();
		return ciphertextChunk;
	}

	@Override
	public void encryptChunk(ByteBuffer cleartextChunk, ByteBuffer ciphertextChunk, long chunkNumber, FileHeader header) {
		if (cleartextChunk.remaining() <= 0 || cleartextChunk.remaining() > PAYLOAD_SIZE) {
			throw new IllegalArgumentException("Invalid cleartext chunk size: " + cleartextChunk.remaining() + ", expected range [1, " + PAYLOAD_SIZE + "]");
		}
		if (ciphertextChunk.remaining() < CHUNK_SIZE) {
			throw new IllegalArgumentException("Invalid cipehrtext chunk size: " + ciphertextChunk.remaining() + ", must fit up to " + CHUNK_SIZE + " bytes.");
		}
		FileHeaderImpl headerImpl = FileHeaderImpl.cast(header);
		encryptChunk(cleartextChunk, ciphertextChunk, chunkNumber, headerImpl.getNonce(), headerImpl.getPayload().getContentKey());
	}

	@Override
	public ByteBuffer decryptChunk(ByteBuffer ciphertextChunk, long chunkNumber, FileHeader header, boolean authenticate) throws AuthenticationFailedException {
		ByteBuffer cleartextChunk = ByteBuffer.allocate(PAYLOAD_SIZE);
		decryptChunk(ciphertextChunk, cleartextChunk, chunkNumber, header, authenticate);
		cleartextChunk.flip();
		return cleartextChunk;
	}

	@Override
	public void decryptChunk(ByteBuffer ciphertextChunk, ByteBuffer cleartextChunk, long chunkNumber, FileHeader header, boolean authenticate) throws AuthenticationFailedException {
		if (ciphertextChunk.remaining() < GCM_NONCE_SIZE + GCM_TAG_SIZE || ciphertextChunk.remaining() > CHUNK_SIZE) {
			throw new IllegalArgumentException("Invalid ciphertext chunk size: " + ciphertextChunk.remaining() + ", expected range [" + (GCM_NONCE_SIZE + GCM_TAG_SIZE) + ", " + CHUNK_SIZE + "]");
		}
		if (cleartextChunk.remaining() < PAYLOAD_SIZE) {
			throw new IllegalArgumentException("Invalid cleartext chunk size: " + cleartextChunk.remaining() + ", must fit up to " + PAYLOAD_SIZE + " bytes.");
		}
		if (!authenticate) {
			throw new UnsupportedOperationException("authenticate can not be false");
		}
		FileHeaderImpl headerImpl = FileHeaderImpl.cast(header);
		decryptChunk(ciphertextChunk, cleartextChunk, chunkNumber, headerImpl.getNonce(), headerImpl.getPayload().getContentKey());
	}

	// visible for testing
	void encryptChunk(ByteBuffer cleartextChunk, ByteBuffer ciphertextChunk, long chunkNumber, byte[] headerNonce, SecretKey fileKey) {
		try {
			// nonce:
			byte[] nonce = new byte[GCM_NONCE_SIZE];
			random.nextBytes(nonce);

			// payload:
			final Cipher cipher = CipherSupplier.AES_GCM.forEncryption(fileKey, new GCMParameterSpec(GCM_TAG_SIZE * Byte.SIZE, nonce));
			final byte[] chunkNumberBigEndian = longToBigEndianByteArray(chunkNumber);
			cipher.updateAAD(chunkNumberBigEndian);
			cipher.updateAAD(headerNonce);
			ciphertextChunk.put(nonce);
			assert ciphertextChunk.remaining() >= cipher.getOutputSize(cleartextChunk.remaining());
			cipher.doFinal(cleartextChunk, ciphertextChunk);
		} catch (ShortBufferException e) {
			throw new IllegalStateException("Buffer allocated for reported output size apparently not big enough.", e);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new IllegalStateException("Unexpected exception during GCM encryption.", e);
		}
	}

	// visible for testing
	void decryptChunk(ByteBuffer ciphertextChunk, ByteBuffer cleartextChunk, long chunkNumber, byte[] headerNonce, SecretKey fileKey) throws AuthenticationFailedException {
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
			assert cleartextChunk.remaining() >= cipher.getOutputSize(payloadBuf.remaining());
			cipher.doFinal(payloadBuf, cleartextChunk);
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
