/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v1;

import static org.cryptomator.cryptolib.v1.Constants.CHUNK_SIZE;
import static org.cryptomator.cryptolib.v1.Constants.MAC_SIZE;
import static org.cryptomator.cryptolib.v1.Constants.NONCE_SIZE;
import static org.cryptomator.cryptolib.v1.Constants.PAYLOAD_SIZE;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.FileContentCryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.common.CipherSupplier;
import org.cryptomator.cryptolib.common.MacSupplier;

class FileContentCryptorImpl implements FileContentCryptor {

	private final SecretKey macKey;
	private final SecureRandom random;

	FileContentCryptorImpl(SecretKey macKey, SecureRandom random) {
		this.macKey = macKey;
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
		if (ciphertextChunk.remaining() < NONCE_SIZE + MAC_SIZE || ciphertextChunk.remaining() > CHUNK_SIZE) {
			throw new IllegalArgumentException("Invalid chunk size: " + ciphertextChunk.remaining() + ", expected range [" + (NONCE_SIZE + MAC_SIZE) + ", " + CHUNK_SIZE + "]");
		}
		FileHeaderImpl headerImpl = FileHeaderImpl.cast(header);
		if (authenticate && !checkChunkMac(headerImpl.getNonce(), chunkNumber, ciphertextChunk.asReadOnlyBuffer())) {
			throw new AuthenticationFailedException("Authentication of chunk " + chunkNumber + " failed.");
		} else {
			return decryptChunk(ciphertextChunk.asReadOnlyBuffer(), headerImpl.getPayload().getContentKey());
		}
	}

	// visible for testing
	ByteBuffer encryptChunk(ByteBuffer cleartextChunk, long chunkNumber, byte[] headerNonce, SecretKey fileKey) {
		try {
			// nonce:
			byte[] nonce = new byte[NONCE_SIZE];
			random.nextBytes(nonce);

			// payload:
			final Cipher cipher = CipherSupplier.AES_CTR.forEncryption(fileKey, new IvParameterSpec(nonce));
			final ByteBuffer outBuf = ByteBuffer.allocate(NONCE_SIZE + cipher.getOutputSize(cleartextChunk.remaining()) + MAC_SIZE);
			outBuf.put(nonce);
			int bytesEncrypted = cipher.doFinal(cleartextChunk, outBuf);

			// mac:
			final ByteBuffer ciphertextBuf = outBuf.asReadOnlyBuffer();
			ciphertextBuf.position(NONCE_SIZE).limit(NONCE_SIZE + bytesEncrypted);
			byte[] authenticationCode = calcChunkMac(macKey, headerNonce, chunkNumber, nonce, ciphertextBuf);
			assert authenticationCode.length == MAC_SIZE;
			outBuf.put(authenticationCode);

			// flip and return:
			outBuf.flip();
			return outBuf;
		} catch (ShortBufferException e) {
			throw new IllegalStateException("Buffer allocated for reported output size apparently not big enough.", e);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new IllegalStateException("Unexpected exception for CTR ciphers.", e);
		}
	}

	// visible for testing
	ByteBuffer decryptChunk(ByteBuffer ciphertextChunk, SecretKey fileKey) {
		assert ciphertextChunk.remaining() >= NONCE_SIZE + MAC_SIZE;

		try {
			// nonce:
			final byte[] nonce = new byte[NONCE_SIZE];
			final ByteBuffer chunkNonceBuf = ciphertextChunk.asReadOnlyBuffer();
			chunkNonceBuf.position(0).limit(NONCE_SIZE);
			chunkNonceBuf.get(nonce);

			// payload:
			final ByteBuffer payloadBuf = ciphertextChunk.asReadOnlyBuffer();
			payloadBuf.position(NONCE_SIZE).limit(ciphertextChunk.limit() - MAC_SIZE);

			// payload:
			final Cipher cipher = CipherSupplier.AES_CTR.forDecryption(fileKey, new IvParameterSpec(nonce));
			final ByteBuffer outBuf = ByteBuffer.allocate(cipher.getOutputSize(payloadBuf.remaining()));
			cipher.doFinal(payloadBuf, outBuf);

			// flip and return:
			outBuf.flip();
			return outBuf;
		} catch (ShortBufferException e) {
			throw new IllegalStateException("Buffer allocated for reported output size apparently not big enough.", e);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new IllegalStateException("Unexpected exception for CTR ciphers.", e);
		}
	}

	// visible for testing
	boolean checkChunkMac(byte[] headerNonce, long chunkNumber, ByteBuffer chunkBuf) {
		assert chunkBuf.remaining() >= NONCE_SIZE + MAC_SIZE;

		// get three components: nonce + payload + mac
		final ByteBuffer chunkNonceBuf = chunkBuf.asReadOnlyBuffer();
		chunkNonceBuf.position(0).limit(NONCE_SIZE);
		final ByteBuffer payloadBuf = chunkBuf.asReadOnlyBuffer();
		payloadBuf.position(NONCE_SIZE).limit(chunkBuf.limit() - MAC_SIZE);
		final ByteBuffer expectedMacBuf = chunkBuf.asReadOnlyBuffer();
		expectedMacBuf.position(chunkBuf.limit() - MAC_SIZE);

		// get nonce:
		final byte[] chunkNonce = new byte[NONCE_SIZE];
		chunkNonceBuf.get(chunkNonce);

		// get expected MAC:
		final byte[] expectedMac = new byte[MAC_SIZE];
		expectedMacBuf.get(expectedMac);

		// get actual MAC:
		final byte[] calculatedMac = calcChunkMac(macKey, headerNonce, chunkNumber, chunkNonce, payloadBuf);

		// time-constant equality check of two MACs:
		return MessageDigest.isEqual(expectedMac, calculatedMac);
	}

	private static byte[] calcChunkMac(SecretKey macKey, byte[] headerNonce, long chunkNumber, byte[] chunkNonce, ByteBuffer ciphertext) {
		final byte[] chunkNumberBigEndian = ByteBuffer.allocate(Long.SIZE / Byte.SIZE).order(ByteOrder.BIG_ENDIAN).putLong(chunkNumber).array();
		final Mac mac = MacSupplier.HMAC_SHA256.withKey(macKey);
		mac.update(headerNonce);
		mac.update(chunkNumberBigEndian);
		mac.update(chunkNonce);
		mac.update(ciphertext);
		return mac.doFinal();
	}

}
