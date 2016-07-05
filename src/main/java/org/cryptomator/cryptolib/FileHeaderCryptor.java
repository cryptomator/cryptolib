/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

public class FileHeaderCryptor {

	private final SecretKey headerKey;
	private final SecretKey macKey;
	private final SecureRandom random;

	/**
	 * Package-private constructor.
	 * Use {@link Cryptor#fileHeaderCryptor()} to obtain a FileHeaderCryptor instance.
	 */
	FileHeaderCryptor(SecretKey headerKey, SecretKey macKey, SecureRandom random) {
		this.headerKey = headerKey;
		this.macKey = macKey;
		this.random = random;
	}

	public FileHeader create() {
		byte[] nonce = new byte[FileHeader.NONCE_LEN];
		random.nextBytes(nonce);
		byte[] contentKey = new byte[FileHeader.Payload.CONTENT_KEY_LEN];
		random.nextBytes(contentKey);
		return new FileHeader(nonce, contentKey);
	}

	public ByteBuffer encryptHeader(FileHeader header) {
		ByteBuffer payloadCleartextBuf = ByteBuffer.allocate(FileHeader.Payload.SIZE);
		payloadCleartextBuf.putLong(header.getPayload().getFilesize());
		payloadCleartextBuf.put(header.getPayload().getContentKeyBytes());
		payloadCleartextBuf.flip();
		try {
			ByteBuffer result = ByteBuffer.allocate(FileHeader.SIZE);
			result.put(header.getNonce());

			// encrypt payload:
			Cipher cipher = CipherSupplier.AES_CTR.forEncryption(headerKey, new IvParameterSpec(header.getNonce()));
			cipher.update(payloadCleartextBuf, result);

			// mac nonce and ciphertext:
			ByteBuffer nonceAndCiphertextBuf = result.duplicate();
			nonceAndCiphertextBuf.flip();
			Mac mac = MacSupplier.HMAC_SHA256.withKey(macKey);
			mac.update(nonceAndCiphertextBuf);
			result.put(mac.doFinal());

			result.flip();
			return result;
		} catch (ShortBufferException e) {
			throw new IllegalStateException("Result buffer too small for encrypted header payload.", e);
		} finally {
			Arrays.fill(payloadCleartextBuf.array(), (byte) 0x00);
		}
	}

	public FileHeader decryptHeader(ByteBuffer ciphertextHeaderBuf) throws AuthenticationFailedException {
		if (ciphertextHeaderBuf.remaining() < FileHeader.SIZE) {
			throw new IllegalStateException("Malformed ciphertext header");
		}
		ByteBuffer buf = ciphertextHeaderBuf.asReadOnlyBuffer();
		byte[] nonce = new byte[FileHeader.NONCE_LEN];
		buf.position(FileHeader.NONCE_POS);
		buf.get(nonce);
		byte[] ciphertextPayload = new byte[FileHeader.PAYLOAD_LEN];
		buf.position(FileHeader.PAYLOAD_POS);
		buf.get(ciphertextPayload);
		byte[] expectedMac = new byte[FileHeader.MAC_LEN];
		buf.position(FileHeader.MAC_POS);
		buf.get(expectedMac);

		// check mac:
		ByteBuffer nonceAndCiphertextBuf = buf.duplicate();
		nonceAndCiphertextBuf.position(FileHeader.NONCE_POS).limit(FileHeader.NONCE_POS + FileHeader.NONCE_LEN + FileHeader.PAYLOAD_LEN);
		Mac mac = MacSupplier.HMAC_SHA256.withKey(macKey);
		mac.update(nonceAndCiphertextBuf);
		byte[] calculatedMac = mac.doFinal();
		if (!MessageDigest.isEqual(expectedMac, calculatedMac)) {
			throw new AuthenticationFailedException("Header MAC doesn't match.");
		}

		// decrypt payload:
		Cipher cipher = CipherSupplier.AES_CTR.forDecryption(headerKey, new IvParameterSpec(nonce));
		byte[] plaintextPayload = cipher.update(ciphertextPayload);
		if (plaintextPayload == null) {
			throw new IllegalStateException("Stream cipher returned null, even though this is only specified for block ciphers.");
		}
		try {
			ByteBuffer plaintextBuf = ByteBuffer.wrap(plaintextPayload);
			plaintextBuf.position(FileHeader.Payload.FILESIZE_POS);
			long fileSize = plaintextBuf.getLong();
			plaintextBuf.position(FileHeader.Payload.CONTENT_KEY_POS);
			byte[] contentKey = new byte[FileHeader.Payload.CONTENT_KEY_LEN];
			plaintextBuf.get(contentKey);

			final FileHeader header = new FileHeader(nonce, contentKey);
			header.getPayload().setFilesize(fileSize);
			return header;
		} finally {
			Arrays.fill(plaintextPayload, (byte) 0x00);
		}
	}

}
