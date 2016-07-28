/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v1;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.cryptomator.cryptolib.common.CipherSupplier;
import org.cryptomator.cryptolib.common.MacSupplier;

public class FileHeaderCryptorImpl implements FileHeaderCryptor {

	private final SecretKey headerKey;
	private final SecretKey macKey;
	private final SecureRandom random;

	/**
	 * Package-private constructor.
	 * Use {@link CryptorImpl#fileHeaderCryptor()} to obtain a FileHeaderCryptor instance.
	 */
	FileHeaderCryptorImpl(SecretKey headerKey, SecretKey macKey, SecureRandom random) {
		this.headerKey = headerKey;
		this.macKey = macKey;
		this.random = random;
	}

	@Override
	public FileHeaderImpl create() {
		byte[] nonce = new byte[FileHeaderImpl.NONCE_LEN];
		random.nextBytes(nonce);
		byte[] contentKey = new byte[FileHeaderImpl.Payload.CONTENT_KEY_LEN];
		random.nextBytes(contentKey);
		return new FileHeaderImpl(nonce, contentKey);
	}

	@Override
	public int headerSize() {
		return FileHeaderImpl.SIZE;
	}

	@Override
	public ByteBuffer encryptHeader(FileHeader header) {
		FileHeaderImpl headerImpl = FileHeaderImpl.cast(header);
		ByteBuffer payloadCleartextBuf = ByteBuffer.allocate(FileHeaderImpl.Payload.SIZE);
		payloadCleartextBuf.putLong(header.getFilesize());
		payloadCleartextBuf.put(headerImpl.getPayload().getContentKeyBytes());
		payloadCleartextBuf.flip();
		try {
			ByteBuffer result = ByteBuffer.allocate(FileHeaderImpl.SIZE);
			result.put(headerImpl.getNonce());

			// encrypt payload:
			Cipher cipher = CipherSupplier.AES_CTR.forEncryption(headerKey, new IvParameterSpec(headerImpl.getNonce()));
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

	@Override
	public FileHeaderImpl decryptHeader(ByteBuffer ciphertextHeaderBuf) throws AuthenticationFailedException {
		if (ciphertextHeaderBuf.remaining() < FileHeaderImpl.SIZE) {
			throw new IllegalArgumentException("Malformed ciphertext header");
		}
		ByteBuffer buf = ciphertextHeaderBuf.asReadOnlyBuffer();
		byte[] nonce = new byte[FileHeaderImpl.NONCE_LEN];
		buf.position(FileHeaderImpl.NONCE_POS);
		buf.get(nonce);
		byte[] ciphertextPayload = new byte[FileHeaderImpl.PAYLOAD_LEN];
		buf.position(FileHeaderImpl.PAYLOAD_POS);
		buf.get(ciphertextPayload);
		byte[] expectedMac = new byte[FileHeaderImpl.MAC_LEN];
		buf.position(FileHeaderImpl.MAC_POS);
		buf.get(expectedMac);

		// check mac:
		ByteBuffer nonceAndCiphertextBuf = buf.duplicate();
		nonceAndCiphertextBuf.position(FileHeaderImpl.NONCE_POS).limit(FileHeaderImpl.NONCE_POS + FileHeaderImpl.NONCE_LEN + FileHeaderImpl.PAYLOAD_LEN);
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
			plaintextBuf.position(FileHeaderImpl.Payload.FILESIZE_POS);
			long fileSize = plaintextBuf.getLong();
			plaintextBuf.position(FileHeaderImpl.Payload.CONTENT_KEY_POS);
			byte[] contentKey = new byte[FileHeaderImpl.Payload.CONTENT_KEY_LEN];
			plaintextBuf.get(contentKey);

			final FileHeaderImpl header = new FileHeaderImpl(nonce, contentKey);
			header.setFilesize(fileSize);
			return header;
		} finally {
			Arrays.fill(plaintextPayload, (byte) 0x00);
		}
	}

}
