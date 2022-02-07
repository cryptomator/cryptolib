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
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.common.CipherSupplier;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;
import org.cryptomator.cryptolib.common.ObjectPool;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.cryptomator.cryptolib.v2.Constants.GCM_TAG_SIZE;

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
		try (DestroyableSecretKey ek = masterkey.getEncKey()) {
			ByteBuffer result = ByteBuffer.allocate(FileHeaderImpl.SIZE);
			result.put(headerImpl.getNonce());

			// encrypt payload:
			try (ObjectPool.Lease<Cipher> cipher = CipherSupplier.AES_GCM.encryptionCipher(ek, new GCMParameterSpec(GCM_TAG_SIZE * Byte.SIZE, headerImpl.getNonce()))) {
				int encrypted = cipher.get().doFinal(payloadCleartextBuf, result);
				assert encrypted == FileHeaderImpl.PAYLOAD_LEN + FileHeaderImpl.TAG_LEN;
			}
			result.flip();
			return result;
		} catch (ShortBufferException e) {
			throw new IllegalStateException("Result buffer too small for encrypted header payload.", e);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new IllegalStateException("Unexpected exception during GCM encryption.", e);
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
		byte[] ciphertextAndTag = new byte[FileHeaderImpl.PAYLOAD_LEN + FileHeaderImpl.TAG_LEN];
		buf.position(FileHeaderImpl.PAYLOAD_POS);
		buf.get(ciphertextAndTag);

		// FileHeaderImpl.Payload.SIZE + GCM_TAG_SIZE is required to fix a bug in Android API level pre 29, see https://issuetracker.google.com/issues/197534888
		ByteBuffer payloadCleartextBuf = ByteBuffer.allocate(FileHeaderImpl.Payload.SIZE + GCM_TAG_SIZE);
		try (DestroyableSecretKey ek = masterkey.getEncKey()) {
			// decrypt payload:
			try (ObjectPool.Lease<Cipher> cipher = CipherSupplier.AES_GCM.decryptionCipher(ek, new GCMParameterSpec(GCM_TAG_SIZE * Byte.SIZE, nonce))) {
				int decrypted = cipher.get().doFinal(ByteBuffer.wrap(ciphertextAndTag), payloadCleartextBuf);
				assert decrypted == FileHeaderImpl.Payload.SIZE;
			}
			payloadCleartextBuf.flip();
			FileHeaderImpl.Payload payload = FileHeaderImpl.Payload.decode(payloadCleartextBuf);

			return new FileHeaderImpl(nonce, payload);
		} catch (AEADBadTagException e) {
			throw new AuthenticationFailedException("Header tag mismatch.", e);
		} catch (ShortBufferException e) {
			throw new IllegalStateException("Result buffer too small for decrypted header payload.", e);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new IllegalStateException("Unexpected exception during GCM decryption.", e);
		} finally {
			Arrays.fill(payloadCleartextBuf.array(), (byte) 0x00);
		}
	}

}
