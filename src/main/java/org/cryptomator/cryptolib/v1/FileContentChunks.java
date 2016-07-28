/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v1;

import static org.cryptomator.cryptolib.v1.Constants.MAC_SIZE;
import static org.cryptomator.cryptolib.v1.Constants.NONCE_SIZE;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

import org.cryptomator.cryptolib.common.CipherSupplier;
import org.cryptomator.cryptolib.common.MacSupplier;

final class FileContentChunks {

	private FileContentChunks() {
	}

	public static ByteBuffer encryptChunk(ByteBuffer cleartextChunk, long chunkNumber, byte[] headerNonce, SecretKey fileKey, SecretKey macKey, SecureRandom randomSource) {
		try {
			// nonce:
			byte[] nonce = new byte[NONCE_SIZE];
			randomSource.nextBytes(nonce);

			// payload:
			final Cipher cipher = CipherSupplier.AES_CTR.forEncryption(fileKey, new IvParameterSpec(nonce));
			final ByteBuffer outBuf = ByteBuffer.allocate(NONCE_SIZE + cipher.getOutputSize(cleartextChunk.remaining()) + MAC_SIZE);
			outBuf.put(nonce);
			int bytesEncrypted = cipher.update(cleartextChunk, outBuf);

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
		}
	}

	public static ByteBuffer decryptChunk(ByteBuffer ciphertextChunk, SecretKey fileKey) {
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
			cipher.update(payloadBuf, outBuf);

			// flip and return:
			outBuf.flip();
			return outBuf;
		} catch (ShortBufferException e) {
			throw new IllegalStateException("Buffer allocated for reported output size apparently not big enough.", e);
		}
	}

	public static boolean checkChunkMac(SecretKey macKey, byte[] headerNonce, long chunkNumber, ByteBuffer chunkBuf) {
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
