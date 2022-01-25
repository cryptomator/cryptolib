/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v1;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.common.CipherSupplier;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;
import org.cryptomator.cryptolib.common.MacSupplier;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

class FileHeaderCryptorImpl implements FileHeaderCryptor {

	private final Masterkey masterkey;
	private final SecureRandom random;

	FileHeaderCryptorImpl(Masterkey masterkey, SecureRandom random) {
		this.masterkey = masterkey;
		this.random = random;
	}

	@Override
	public FileHeader create() {
		byte[] nonce = new byte[FileHeaderImpl.NONCE_LEN];
		random.nextBytes(nonce);
		byte[] contentKey = new byte[FileHeaderImpl.Payload.CONTENT_KEY_LEN];
		random.nextBytes(contentKey);
		FileHeaderImpl.Payload payload = new FileHeaderImpl.Payload(-1, contentKey);
		return new FileHeaderImpl(nonce, payload);
	}

	@Override
	public int headerSize() {
		return FileHeaderImpl.SIZE;
	}

	@Override
	public ByteBuffer encryptHeader(FileHeader header) {
		FileHeaderImpl headerImpl = FileHeaderImpl.cast(header);
		ByteBuffer payloadCleartextBuf = headerImpl.getPayload().encode();
		try (DestroyableSecretKey ek = masterkey.getEncKey(); DestroyableSecretKey mk = masterkey.getMacKey()) {
			ByteBuffer result = ByteBuffer.allocate(FileHeaderImpl.SIZE);
			result.put(headerImpl.getNonce());

			// encrypt payload:
			Cipher cipher = CipherSupplier.AES_CTR.forEncryption(ek, new IvParameterSpec(headerImpl.getNonce()));
			int encrypted = cipher.doFinal(payloadCleartextBuf, result);
			assert encrypted == FileHeaderImpl.Payload.SIZE;

			// mac nonce and ciphertext:
			ByteBuffer nonceAndCiphertextBuf = result.duplicate();
			nonceAndCiphertextBuf.flip();
			Mac mac = MacSupplier.HMAC_SHA256.withKey(mk);
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
		ByteBuffer buf = ciphertextHeaderBuf.duplicate();
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
		try (DestroyableSecretKey mk = masterkey.getMacKey()) {
			ByteBuffer nonceAndCiphertextBuf = buf.duplicate();
			nonceAndCiphertextBuf.position(FileHeaderImpl.NONCE_POS).limit(FileHeaderImpl.NONCE_POS + FileHeaderImpl.NONCE_LEN + FileHeaderImpl.PAYLOAD_LEN);
			Mac mac = MacSupplier.HMAC_SHA256.withKey(mk);
			mac.update(nonceAndCiphertextBuf);
			byte[] calculatedMac = mac.doFinal();
			if (!MessageDigest.isEqual(expectedMac, calculatedMac)) {
				throw new AuthenticationFailedException("Header MAC doesn't match.");
			}
		}

		ByteBuffer payloadCleartextBuf = ByteBuffer.allocate(FileHeaderImpl.Payload.SIZE);
		try (DestroyableSecretKey ek = masterkey.getEncKey()) {
			// decrypt payload:
			Cipher cipher = CipherSupplier.AES_CTR.forDecryption(ek, new IvParameterSpec(nonce));
			assert cipher.getOutputSize(ciphertextPayload.length) == payloadCleartextBuf.remaining();
			int decrypted = cipher.doFinal(ByteBuffer.wrap(ciphertextPayload), payloadCleartextBuf);
			assert decrypted == FileHeaderImpl.Payload.SIZE;
			payloadCleartextBuf.flip();
			FileHeaderImpl.Payload payload = FileHeaderImpl.Payload.decode(payloadCleartextBuf);

			return new FileHeaderImpl(nonce, payload);
		} catch (ShortBufferException e) {
			throw new IllegalStateException("Result buffer too small for decrypted header payload.", e);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new IllegalStateException("Unexpected exception for CTR ciphers.", e);
		} finally {
			Arrays.fill(payloadCleartextBuf.array(), (byte) 0x00);
		}
	}

}
