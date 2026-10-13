package org.cryptomator.cryptolib.cvf8;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.CvfMasterkey;
import org.cryptomator.cryptolib.common.CipherSupplier;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;
import org.cryptomator.cryptolib.common.ObjectPool;
import org.cryptomator.cryptolib.internal.FileHeaderParts;
import org.cryptomator.cryptolib.internal.FileLayout;

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

import static org.cryptomator.cryptolib.cvf8.Constants.CONTENT_ENC_ALG;
import static org.cryptomator.cryptolib.cvf8.Constants.GCM_CHUNK_SIZE;
import static org.cryptomator.cryptolib.cvf8.Constants.GCM_NONCE_SIZE;
import static org.cryptomator.cryptolib.cvf8.Constants.GCM_TAG_SIZE;
import static org.cryptomator.cryptolib.cvf8.Constants.HEADER_CONTENT_KEY_LEN;
import static org.cryptomator.cryptolib.cvf8.Constants.HEADER_PAYLOAD_LEN;
import static org.cryptomator.cryptolib.cvf8.Constants.HEADER_RESERVED_VALUE;
import static org.cryptomator.cryptolib.cvf8.Constants.PAYLOAD_SIZE;

/**
 * {@link org.cryptomator.cryptolib.api.CipherCombo#SIV_GCM}: AES-GCM for headers (68 bytes) and chunks (12 nonce + payload + 16 tag).
 */
final class GcmCodec implements Cvf8ContentCodec {

	private static final int HEADER_NONCE_POS = 0;
	private static final int HEADER_PAYLOAD_POS = HEADER_NONCE_POS + GCM_NONCE_SIZE; // 12
	private static final int HEADER_TAG_POS = HEADER_PAYLOAD_POS + HEADER_PAYLOAD_LEN; // 52
	private static final int HEADER_SIZE = HEADER_TAG_POS + GCM_TAG_SIZE; // 68
	private static final FileLayout LAYOUT = new FileLayout(HEADER_SIZE, PAYLOAD_SIZE, GCM_CHUNK_SIZE, false);

	private final CvfMasterkey masterkey;
	private final SecureRandom random;

	GcmCodec(CvfMasterkey masterkey, SecureRandom random) {
		this.masterkey = masterkey;
		this.random = random;
	}

	@Override
	public FileLayout layout() {
		return LAYOUT;
	}

	// HEADER

	@Override
	public FileHeaderParts createHeader() {
		byte[] nonce = new byte[GCM_NONCE_SIZE];
		random.nextBytes(nonce);
		byte[] contentKey = new byte[HEADER_CONTENT_KEY_LEN];
		random.nextBytes(contentKey);
		try {
			ByteBuffer payloadCleartext = ByteBuffer.allocate(HEADER_PAYLOAD_LEN);
			payloadCleartext.putLong(HEADER_RESERVED_VALUE);
			payloadCleartext.put(contentKey);
			payloadCleartext.flip();
			ByteBuffer encrypted = encryptHeader(nonce, payloadCleartext);
			return new FileHeaderParts(encrypted, nonce, new DestroyableSecretKey(contentKey, CONTENT_ENC_ALG), 0);
		} finally {
			Arrays.fill(contentKey, (byte) 0x00);
		}
	}

	private ByteBuffer encryptHeader(byte[] nonce, ByteBuffer payloadCleartext) {
		try (DestroyableSecretKey ek = masterkey.getEncKey()) {
			ByteBuffer result = ByteBuffer.allocate(HEADER_SIZE);
			result.put(nonce);
			try (ObjectPool.Lease<Cipher> cipher = CipherSupplier.AES_GCM.encryptionCipher(ek, new GCMParameterSpec(GCM_TAG_SIZE * Byte.SIZE, nonce))) {
				int encrypted = cipher.get().doFinal(payloadCleartext, result);
				assert encrypted == HEADER_PAYLOAD_LEN + GCM_TAG_SIZE;
			}
			result.flip();
			return result;
		} catch (ShortBufferException e) {
			throw new IllegalStateException("Result buffer too small for encrypted header payload.", e);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new IllegalStateException("Unexpected exception during GCM encryption.", e);
		} finally {
			Arrays.fill(payloadCleartext.array(), (byte) 0x00);
		}
	}

	@Override
	public FileHeaderParts decryptHeader(ByteBuffer encryptedHeader) throws AuthenticationFailedException {
		if (encryptedHeader.remaining() < HEADER_SIZE) {
			throw new IllegalArgumentException("Malformed ciphertext header");
		}
		ByteBuffer buf = encryptedHeader.slice();
		buf.limit(HEADER_SIZE);
		byte[] nonce = new byte[GCM_NONCE_SIZE];
		buf.position(HEADER_NONCE_POS);
		buf.get(nonce);
		byte[] ciphertextAndTag = new byte[HEADER_PAYLOAD_LEN + GCM_TAG_SIZE];
		buf.position(HEADER_PAYLOAD_POS);
		buf.get(ciphertextAndTag);

		// HEADER_PAYLOAD_LEN + GCM_TAG_SIZE is required to fix a bug in Android API level pre 29, see https://issuetracker.google.com/issues/197534888 and #24
		ByteBuffer payloadCleartext = ByteBuffer.allocate(HEADER_PAYLOAD_LEN + GCM_TAG_SIZE);
		try (DestroyableSecretKey ek = masterkey.getEncKey()) {
			try (ObjectPool.Lease<Cipher> cipher = CipherSupplier.AES_GCM.decryptionCipher(ek, new GCMParameterSpec(GCM_TAG_SIZE * Byte.SIZE, nonce))) {
				int decrypted = cipher.get().doFinal(ByteBuffer.wrap(ciphertextAndTag), payloadCleartext);
				assert decrypted == HEADER_PAYLOAD_LEN;
			}
			payloadCleartext.flip();
			payloadCleartext.getLong(); // reserved, ignored
			byte[] contentKey = new byte[HEADER_CONTENT_KEY_LEN];
			payloadCleartext.get(contentKey);
			try {
				ByteBuffer copy = ByteBuffer.allocate(HEADER_SIZE);
				buf.rewind();
				copy.put(buf);
				copy.flip();
				return new FileHeaderParts(copy, nonce, new DestroyableSecretKey(contentKey, CONTENT_ENC_ALG), 0);
			} finally {
				Arrays.fill(contentKey, (byte) 0x00);
			}
		} catch (AEADBadTagException e) {
			throw new AuthenticationFailedException("Header tag mismatch.", e);
		} catch (ShortBufferException e) {
			throw new IllegalStateException("Result buffer too small for decrypted header payload.", e);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new IllegalStateException("Unexpected exception during GCM decryption.", e);
		} finally {
			Arrays.fill(payloadCleartext.array(), (byte) 0x00);
		}
	}

	// CHUNKS

	@Override
	public void encryptChunk(byte[] headerNonce, DestroyableSecretKey fileKey, ByteBuffer cleartextChunk, ByteBuffer ciphertextChunk, long chunkIndex) {
		if (cleartextChunk.remaining() > PAYLOAD_SIZE) {
			throw new IllegalArgumentException("Invalid cleartext chunk size: " + cleartextChunk.remaining() + ", expected range [0, " + PAYLOAD_SIZE + "]");
		}
		if (ciphertextChunk.remaining() < cleartextChunk.remaining() + GCM_NONCE_SIZE + GCM_TAG_SIZE) {
			throw new IllegalArgumentException("Invalid ciphertext chunk size: " + ciphertextChunk.remaining() + ", must fit " + (cleartextChunk.remaining() + GCM_NONCE_SIZE + GCM_TAG_SIZE) + " bytes.");
		}
		try (DestroyableSecretKey fk = fileKey.copy()) {
			byte[] nonce = new byte[GCM_NONCE_SIZE];
			random.nextBytes(nonce);
			try (ObjectPool.Lease<Cipher> cipher = CipherSupplier.AES_GCM.encryptionCipher(fk, new GCMParameterSpec(GCM_TAG_SIZE * Byte.SIZE, nonce))) {
				cipher.get().updateAAD(longToBigEndianByteArray(chunkIndex));
				cipher.get().updateAAD(headerNonce);
				ciphertextChunk.put(nonce);
				cipher.get().doFinal(cleartextChunk, ciphertextChunk);
			}
		} catch (ShortBufferException e) {
			throw new IllegalStateException("Buffer allocated for reported output size apparently not big enough.", e);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new IllegalStateException("Unexpected exception during GCM encryption.", e);
		}
	}

	@Override
	public void decryptChunk(byte[] headerNonce, DestroyableSecretKey fileKey, ByteBuffer ciphertextChunk, ByteBuffer cleartextChunk, long chunkIndex) throws AuthenticationFailedException {
		if (ciphertextChunk.remaining() < GCM_NONCE_SIZE + GCM_TAG_SIZE || ciphertextChunk.remaining() > GCM_CHUNK_SIZE) {
			throw new IllegalArgumentException("Invalid ciphertext chunk size: " + ciphertextChunk.remaining() + ", expected range [" + (GCM_NONCE_SIZE + GCM_TAG_SIZE) + ", " + GCM_CHUNK_SIZE + "]");
		}
		if (cleartextChunk.remaining() < ciphertextChunk.remaining() - GCM_NONCE_SIZE - GCM_TAG_SIZE) {
			throw new IllegalArgumentException("Invalid cleartext chunk size: " + cleartextChunk.remaining() + ", must fit " + (ciphertextChunk.remaining() - GCM_NONCE_SIZE - GCM_TAG_SIZE) + " bytes.");
		}
		try (DestroyableSecretKey fk = fileKey.copy()) {
			byte[] nonce = new byte[GCM_NONCE_SIZE];
			ciphertextChunk.get(nonce, 0, GCM_NONCE_SIZE);
			try (ObjectPool.Lease<Cipher> cipher = CipherSupplier.AES_GCM.decryptionCipher(fk, new GCMParameterSpec(GCM_TAG_SIZE * Byte.SIZE, nonce))) {
				cipher.get().updateAAD(longToBigEndianByteArray(chunkIndex));
				cipher.get().updateAAD(headerNonce);
				cipher.get().doFinal(ciphertextChunk, cleartextChunk);
			}
		} catch (AEADBadTagException e) {
			throw new AuthenticationFailedException("Content tag mismatch.", e);
		} catch (ShortBufferException e) {
			throw new IllegalStateException("Buffer allocated for reported output size apparently not big enough.", e);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new IllegalStateException("Unexpected exception during GCM decryption.", e);
		}
	}

	private static byte[] longToBigEndianByteArray(long n) {
		return ByteBuffer.allocate(Long.BYTES).order(ByteOrder.BIG_ENDIAN).putLong(n).array();
	}

}
