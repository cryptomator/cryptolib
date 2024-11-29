package org.cryptomator.cryptolib.v3;

import org.cryptomator.cryptolib.api.*;
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
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import static org.cryptomator.cryptolib.v3.Constants.GCM_TAG_SIZE;

class FileHeaderCryptorImpl implements FileHeaderCryptor {

	private static final byte[] KDF_CONTEXT = "fileHeader".getBytes(StandardCharsets.US_ASCII);

	private final RevolvingMasterkey masterkey;
	private final SecureRandom random;

	FileHeaderCryptorImpl(RevolvingMasterkey masterkey, SecureRandom random) {
		this.masterkey = masterkey;
		this.random = random;
	}

	@Override
	public FileHeader create() {
		byte[] nonce = new byte[FileHeaderImpl.NONCE_LEN];
		random.nextBytes(nonce);
		byte[] contentKeyBytes = new byte[FileHeaderImpl.CONTENT_KEY_LEN];
		random.nextBytes(contentKeyBytes);
		DestroyableSecretKey contentKey = new DestroyableSecretKey(contentKeyBytes, Constants.CONTENT_ENC_ALG);
		return new FileHeaderImpl(nonce, contentKey);
	}

	@Override
	public int headerSize() {
		return FileHeaderImpl.SIZE;
	}

	@Override
	public ByteBuffer encryptHeader(FileHeader header) {
		FileHeaderImpl headerImpl = FileHeaderImpl.cast(header);
		int seedId = masterkey.currentRevision();
		try (DestroyableSecretKey headerKey = masterkey.subKey(seedId, 32, KDF_CONTEXT, "AES")) {
			ByteBuffer result = ByteBuffer.allocate(FileHeaderImpl.SIZE);

			// general header:
			result.put(Constants.UVF_MAGIC_BYTES);
			result.order(ByteOrder.BIG_ENDIAN).putInt(seedId);
			ByteBuffer generalHeaderBuf = result.duplicate();
			generalHeaderBuf.position(0).limit(FileHeaderImpl.UVF_GENERAL_HEADERS_LEN);

			// format-specific header:
			result.put(headerImpl.getNonce());
			try (ObjectPool.Lease<Cipher> cipher = CipherSupplier.AES_GCM.encryptionCipher(headerKey, new GCMParameterSpec(GCM_TAG_SIZE * Byte.SIZE, headerImpl.getNonce()))) {
				cipher.get().updateAAD(generalHeaderBuf);
				ByteBuffer payloadCleartextBuf = ByteBuffer.wrap(headerImpl.getContentKey().getEncoded());
				int encrypted = cipher.get().doFinal(payloadCleartextBuf, result);
				assert encrypted == FileHeaderImpl.CONTENT_KEY_LEN + FileHeaderImpl.TAG_LEN;
			}
			result.flip();
			return result;
		} catch (ShortBufferException e) {
			throw new IllegalStateException("Result buffer too small for encrypted header payload.", e);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new IllegalStateException("Unexpected exception during GCM encryption.", e);
		}
	}

	@Override
	public FileHeaderImpl decryptHeader(ByteBuffer ciphertextHeaderBuf) throws AuthenticationFailedException {
		if (ciphertextHeaderBuf.remaining() < FileHeaderImpl.SIZE) {
			throw new IllegalArgumentException("Malformed ciphertext header");
		}
		ByteBuffer buf = ciphertextHeaderBuf.duplicate();

		// general header:
		byte[] magicBytes = new byte[Constants.UVF_MAGIC_BYTES.length];
		buf.get(magicBytes);
		if (!Arrays.equals(Constants.UVF_MAGIC_BYTES, magicBytes)) {
			throw new IllegalArgumentException("Not an UVF0 file");
		}
		int seedId = buf.order(ByteOrder.BIG_ENDIAN).getInt();
		ByteBuffer generalHeaderBuf = buf.duplicate();
		generalHeaderBuf.position(0).limit(FileHeaderImpl.UVF_GENERAL_HEADERS_LEN);

		// format-specific header:
		byte[] nonce = new byte[FileHeaderImpl.NONCE_LEN];
		buf.position(FileHeaderImpl.NONCE_POS);
		buf.get(nonce);
		byte[] ciphertextAndTag = new byte[FileHeaderImpl.CONTENT_KEY_LEN + FileHeaderImpl.TAG_LEN];
		buf.position(FileHeaderImpl.CONTENT_KEY_POS);
		buf.get(ciphertextAndTag);

		// FileHeaderImpl.Payload.SIZE + GCM_TAG_SIZE is required to fix a bug in Android API level pre 29, see https://issuetracker.google.com/issues/197534888 and #24
		ByteBuffer payloadCleartextBuf = ByteBuffer.allocate(FileHeaderImpl.CONTENT_KEY_LEN + GCM_TAG_SIZE);
		try (DestroyableSecretKey headerKey = masterkey.subKey(seedId, 32, KDF_CONTEXT, "AES")) {
			// decrypt payload:
			try (ObjectPool.Lease<Cipher> cipher = CipherSupplier.AES_GCM.decryptionCipher(headerKey, new GCMParameterSpec(GCM_TAG_SIZE * Byte.SIZE, nonce))) {
				cipher.get().updateAAD(generalHeaderBuf);
				int decrypted = cipher.get().doFinal(ByteBuffer.wrap(ciphertextAndTag), payloadCleartextBuf);
				assert decrypted == FileHeaderImpl.CONTENT_KEY_LEN;
			}
			payloadCleartextBuf.flip();
			byte[] contentKeyBytes = new byte[FileHeaderImpl.CONTENT_KEY_LEN];
			payloadCleartextBuf.get(contentKeyBytes);
			DestroyableSecretKey contentKey = new DestroyableSecretKey(contentKeyBytes, Constants.CONTENT_ENC_ALG);
			return new FileHeaderImpl(nonce, contentKey);
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
