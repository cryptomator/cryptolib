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
import java.security.SecureRandom;
import java.util.Arrays;

import static org.cryptomator.cryptolib.v3.Constants.GCM_TAG_SIZE;

class FileHeaderCryptorImpl implements FileHeaderCryptor {

	private final RevolvingMasterkey masterkey;
	private final SecureRandom random;
	private final int revision;
	private final byte[] kdfContext;

	/**
	 * Creates a header cryptor for regular file content.
	 *
	 * @param masterkey The masterkey from which to derive the header key
	 * @param random A CSPRNG for nonces and file keys
	 * @param revision The seed used for newly created headers
	 */
	FileHeaderCryptorImpl(RevolvingMasterkey masterkey, SecureRandom random, int revision) {
		this(masterkey, random, revision, Constants.KDF_CONTEXT_FILE_HEADER);
	}

	/**
	 * Creates a header cryptor for a specific node type.
	 *
	 * @param masterkey The masterkey from which to derive the header key
	 * @param random A CSPRNG for nonces and file keys
	 * @param revision The seed used for newly created headers
	 * @param kdfContext The header key's KDF context, one of {@link Constants#KDF_CONTEXT_FILE_HEADER}, {@link Constants#KDF_CONTEXT_DIR_HEADER} or {@link Constants#KDF_CONTEXT_SYMLINK_HEADER}
	 */
	FileHeaderCryptorImpl(RevolvingMasterkey masterkey, SecureRandom random, int revision, byte[] kdfContext) {
		this.masterkey = masterkey;
		this.random = random;
		this.revision = revision;
		this.kdfContext = kdfContext;
	}

	@Override
	public FileHeaderImpl create() {
		byte[] nonce = new byte[FileHeaderImpl.NONCE_LEN];
		random.nextBytes(nonce);
		byte[] contentKeyBytes = new byte[FileHeaderImpl.CONTENT_KEY_LEN];
		random.nextBytes(contentKeyBytes);
		DestroyableSecretKey contentKey = new DestroyableSecretKey(contentKeyBytes, Constants.CONTENT_ENC_ALG);
		return new FileHeaderImpl(revision, nonce, contentKey);
	}

	@Override
	public int headerSize() {
		return FileHeaderImpl.SIZE;
	}

	@Override
	public ByteBuffer encryptHeader(FileHeader header) {
		FileHeaderImpl headerImpl = FileHeaderImpl.cast(header);
		try (DestroyableSecretKey headerKey = masterkey.subKey(headerImpl.getSeedId(), 32, kdfContext, "AES")) {
			ByteBuffer result = ByteBuffer.allocate(FileHeaderImpl.SIZE);

			// general header:
			result.put(Constants.UVF_MAGIC_BYTES);
			result.order(ByteOrder.BIG_ENDIAN).putInt(headerImpl.getSeedId());
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

	/**
	 * Decrypts a file header.
	 *
	 * @param ciphertextHeaderBuf The encrypted header
	 * @return The decrypted header
	 * @throws AuthenticationFailedException If the header's tag does not match, e.g. because it was encrypted for a different node type
	 * @throws IllegalArgumentException If the header is too short, is not a UVF header, uses an unsupported spec version or references a seed unknown to the masterkey
	 */
	@Override
	public FileHeaderImpl decryptHeader(ByteBuffer ciphertextHeaderBuf) throws AuthenticationFailedException {
		if (ciphertextHeaderBuf.remaining() < FileHeaderImpl.SIZE) {
			throw new IllegalArgumentException("Malformed ciphertext header");
		}
		ByteBuffer buf = ciphertextHeaderBuf.duplicate();

		// general header:
		byte[] magicBytes = new byte[Constants.UVF_MAGIC.length];
		buf.get(magicBytes);
		if (!Arrays.equals(Constants.UVF_MAGIC, magicBytes)) {
			throw new IllegalArgumentException("Not a UVF file");
		}
		byte specVersion = buf.get();
		if (specVersion != Constants.UVF_SPEC_VERSION) {
			throw new IllegalArgumentException("Unsupported UVF spec version: " + (specVersion & 0xFF));
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
		try (DestroyableSecretKey headerKey = masterkey.subKey(seedId, 32, kdfContext, "AES")) { // throws IllegalArgumentException if the seed ID is not in seeds
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
			return new FileHeaderImpl(seedId, nonce, contentKey);
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
