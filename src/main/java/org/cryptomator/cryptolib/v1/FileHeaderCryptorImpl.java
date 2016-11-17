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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.cryptomator.cryptolib.common.CipherSupplier;
import org.cryptomator.cryptolib.common.MacSupplier;

class FileHeaderCryptorImpl implements FileHeaderCryptor {

	private final SecretKey headerKey;
	private final SecretKey macKey;
	private final SecureRandom random;

	FileHeaderCryptorImpl(SecretKey headerKey, SecretKey macKey, SecureRandom random) {
		this.headerKey = headerKey;
		this.macKey = macKey;
		this.random = random;
	}

	@Override
	public FileHeader create() {
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
		payloadCleartextBuf.putLong(-1l);
		payloadCleartextBuf.put(headerImpl.getPayload().getContentKeyBytes());
		payloadCleartextBuf.flip();
		try {
			ByteBuffer result = ByteBuffer.allocate(FileHeaderImpl.SIZE);
			result.put(headerImpl.getNonce());

			// encrypt payload:
			Cipher cipher = CipherSupplier.AES_CTR.forEncryption(headerKey, new IvParameterSpec(headerImpl.getNonce()));
			int encrypted = cipher.doFinal(payloadCleartextBuf, result);
			assert encrypted == FileHeaderImpl.Payload.SIZE;

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
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new IllegalStateException("Unexpected exception for CTR ciphers.", e);
		} finally {
			Arrays.fill(payloadCleartextBuf.array(), (byte) 0x00);
		}
	}

	@Override
	public FileHeader decryptHeader(ByteBuffer ciphertextHeaderBuf) throws AuthenticationFailedException {
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

		ByteBuffer payloadCleartextBuf = ByteBuffer.allocate(FileHeaderImpl.Payload.SIZE);
		try {
			// decrypt payload:
			Cipher cipher = CipherSupplier.AES_CTR.forDecryption(headerKey, new IvParameterSpec(nonce));
			int decrypted = cipher.doFinal(ByteBuffer.wrap(ciphertextPayload), payloadCleartextBuf);
			assert decrypted == FileHeaderImpl.Payload.SIZE;

			payloadCleartextBuf.position(FileHeaderImpl.Payload.FILESIZE_POS);
			long fileSize = payloadCleartextBuf.getLong();
			payloadCleartextBuf.position(FileHeaderImpl.Payload.CONTENT_KEY_POS);
			byte[] contentKey = new byte[FileHeaderImpl.Payload.CONTENT_KEY_LEN];
			payloadCleartextBuf.get(contentKey);

			final FileHeaderImpl header = new FileHeaderImpl(nonce, contentKey);
			header.setFilesize(fileSize);
			return header;
		} catch (ShortBufferException e) {
			throw new IllegalStateException("Result buffer too small for decrypted header payload.", e);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new IllegalStateException("Unexpected exception for CTR ciphers.", e);
		} finally {
			Arrays.fill(payloadCleartextBuf.array(), (byte) 0x00);
		}
	}

}
