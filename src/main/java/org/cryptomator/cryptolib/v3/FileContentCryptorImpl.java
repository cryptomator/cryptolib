package org.cryptomator.cryptolib.v3;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.FileContentCryptor;
import org.cryptomator.cryptolib.api.FileHeader;
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

import static org.cryptomator.cryptolib.v3.Constants.CHUNK_OVERHEAD;
import static org.cryptomator.cryptolib.v3.Constants.CHUNK_SIZE;
import static org.cryptomator.cryptolib.v3.Constants.GCM_NONCE_SIZE;
import static org.cryptomator.cryptolib.v3.Constants.GCM_TAG_SIZE;
import static org.cryptomator.cryptolib.v3.Constants.MAX_CHUNK_NUMBER;
import static org.cryptomator.cryptolib.v3.Constants.PAYLOAD_SIZE;

/**
 * AES-256-GCM-32k file content encryption.
 * <p>
 * A file body always ends with a trailing chunk that is empty (the EOF chunk) if the cleartext size is a multiple of the chunk size, including the empty file.
 * {@link #cleartextSize(long)} enforces this structure, so a ciphertext size that lacks the EOF chunk is rejected.
 */
class FileContentCryptorImpl implements FileContentCryptor {

	private final SecureRandom random;

	FileContentCryptorImpl(SecureRandom random) {
		this.random = random;
	}

	@Override
	public boolean canSkipAuthentication() {
		return false;
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
	public long cleartextSize(long ciphertextSize) {
		if (ciphertextSize < CHUNK_OVERHEAD) {
			throw new IllegalArgumentException("Ciphertext too short for the EOF chunk: " + ciphertextSize);
		}
		long numFullChunks = ciphertextSize / CHUNK_SIZE;
		long lastChunkSize = ciphertextSize % CHUNK_SIZE;
		if (lastChunkSize == 0) {
			throw new IllegalArgumentException("Missing EOF chunk, ciphertext ends on a full chunk: " + ciphertextSize);
		} else if (lastChunkSize < CHUNK_OVERHEAD) {
			throw new IllegalArgumentException("Impossible size of last chunk: " + lastChunkSize);
		}
		return numFullChunks * PAYLOAD_SIZE + (lastChunkSize - CHUNK_OVERHEAD);
	}

	@Override
	public long ciphertextSize(long cleartextSize) {
		if (cleartextSize < 0) {
			throw new IllegalArgumentException("expected cleartextSize to be positive, but was " + cleartextSize);
		}
		long numFullChunks = cleartextSize / PAYLOAD_SIZE;
		long lastChunkPayload = cleartextSize % PAYLOAD_SIZE; // 0 means an empty EOF chunk
		return numFullChunks * CHUNK_SIZE + CHUNK_OVERHEAD + lastChunkPayload;
	}

	@Override
	public ByteBuffer encryptChunk(ByteBuffer cleartextChunk, long chunkNumber, FileHeader header) {
		ByteBuffer ciphertextChunk = ByteBuffer.allocate(CHUNK_SIZE);
		encryptChunk(cleartextChunk, ciphertextChunk, chunkNumber, header);
		ciphertextChunk.flip();
		return ciphertextChunk;
	}

	@Override
	public void encryptChunk(ByteBuffer cleartextChunk, ByteBuffer ciphertextChunk, long chunkNumber, FileHeader header) {
		if (cleartextChunk.remaining() > PAYLOAD_SIZE) { // an empty chunk is valid: it is the EOF chunk
			throw new IllegalArgumentException("Invalid cleartext chunk size: " + cleartextChunk.remaining() + ", expected range [0, " + PAYLOAD_SIZE + "]");
		}
		if (ciphertextChunk.remaining() < CHUNK_SIZE) {
			throw new IllegalArgumentException("Invalid ciphertext chunk size: " + ciphertextChunk.remaining() + ", must fit up to " + CHUNK_SIZE + " bytes.");
		}
		if (chunkNumber < 0 || chunkNumber > MAX_CHUNK_NUMBER) {
			throw new IllegalArgumentException("Invalid chunk number: " + chunkNumber + "expected range [0, " + Constants.MAX_CHUNK_NUMBER + "]");
		}
		FileHeaderImpl headerImpl = FileHeaderImpl.cast(header);
		encryptChunk(cleartextChunk, ciphertextChunk, chunkNumber, headerImpl.getNonce(), headerImpl.getContentKey());
	}

	@Override
	public ByteBuffer decryptChunk(ByteBuffer ciphertextChunk, long chunkNumber, FileHeader header, boolean authenticate) throws AuthenticationFailedException {
		// FileHeaderImpl.Payload.SIZE + GCM_TAG_SIZE is required to fix a bug in Android API level pre 29, see https://issuetracker.google.com/issues/197534888 and #35
		ByteBuffer cleartextChunk = ByteBuffer.allocate(PAYLOAD_SIZE + GCM_TAG_SIZE);
		decryptChunk(ciphertextChunk, cleartextChunk, chunkNumber, header, authenticate);
		cleartextChunk.flip();
		return cleartextChunk;
	}

	@Override
	public void decryptChunk(ByteBuffer ciphertextChunk, ByteBuffer cleartextChunk, long chunkNumber, FileHeader header, boolean authenticate) throws AuthenticationFailedException {
		if (ciphertextChunk.remaining() < CHUNK_OVERHEAD || ciphertextChunk.remaining() > CHUNK_SIZE) {
			throw new IllegalArgumentException("Invalid ciphertext chunk size: " + ciphertextChunk.remaining() + ", expected range [" + CHUNK_OVERHEAD + ", " + CHUNK_SIZE + "]");
		}
		if (cleartextChunk.remaining() < PAYLOAD_SIZE) {
			throw new IllegalArgumentException("Invalid cleartext chunk size: " + cleartextChunk.remaining() + ", must fit up to " + PAYLOAD_SIZE + " bytes.");
		}
		if (!authenticate) {
			throw new UnsupportedOperationException("authenticate can not be false");
		}
		if (chunkNumber < 0 || chunkNumber > MAX_CHUNK_NUMBER) {
			throw new IllegalArgumentException("Invalid chunk number: " + chunkNumber + "expected range [0, " + Constants.MAX_CHUNK_NUMBER + "]");
		}
		FileHeaderImpl headerImpl = FileHeaderImpl.cast(header);
		decryptChunk(ciphertextChunk, cleartextChunk, chunkNumber, headerImpl.getNonce(), headerImpl.getContentKey());
	}

	// visible for testing
	void encryptChunk(ByteBuffer cleartextChunk, ByteBuffer ciphertextChunk, long chunkNumber, byte[] headerNonce, DestroyableSecretKey fileKey) {
		try (DestroyableSecretKey fk = fileKey.copy()) {
			// nonce:
			byte[] nonce = new byte[GCM_NONCE_SIZE];
			random.nextBytes(nonce);

			// payload:
			try (ObjectPool.Lease<Cipher> cipher = CipherSupplier.AES_GCM.encryptionCipher(fk, new GCMParameterSpec(GCM_TAG_SIZE * Byte.SIZE, nonce))) {
				cipher.get().updateAAD(chunkNumberBigEndian(chunkNumber));
				cipher.get().updateAAD(headerNonce);
				ciphertextChunk.put(nonce);
				assert ciphertextChunk.remaining() >= cipher.get().getOutputSize(cleartextChunk.remaining());
				cipher.get().doFinal(cleartextChunk, ciphertextChunk);
			}
		} catch (ShortBufferException e) {
			throw new IllegalStateException("Buffer allocated for reported output size apparently not big enough.", e);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new IllegalStateException("Unexpected exception during GCM encryption.", e);
		}
	}

	// visible for testing
	void decryptChunk(ByteBuffer ciphertextChunk, ByteBuffer cleartextChunk, long chunkNumber, byte[] headerNonce, DestroyableSecretKey fileKey) throws AuthenticationFailedException {
		assert ciphertextChunk.remaining() >= CHUNK_OVERHEAD;

		try (DestroyableSecretKey fk = fileKey.copy()) {
			// nonce:
			final byte[] nonce = new byte[GCM_NONCE_SIZE];
			ciphertextChunk.get(nonce, 0, GCM_NONCE_SIZE);

			// payload:
			final ByteBuffer payloadBuf = ciphertextChunk.duplicate();
			assert payloadBuf.remaining() >= GCM_TAG_SIZE;

			// payload:
			try (ObjectPool.Lease<Cipher> cipher = CipherSupplier.AES_GCM.decryptionCipher(fk, new GCMParameterSpec(GCM_TAG_SIZE * Byte.SIZE, nonce))) {
				cipher.get().updateAAD(chunkNumberBigEndian(chunkNumber));
				cipher.get().updateAAD(headerNonce);
				assert cleartextChunk.remaining() >= cipher.get().getOutputSize(payloadBuf.remaining());
				cipher.get().doFinal(payloadBuf, cleartextChunk);
			}
		} catch (AEADBadTagException e) {
			throw new AuthenticationFailedException("Content tag mismatch.", e);
		} catch (ShortBufferException e) {
			throw new IllegalStateException("Buffer allocated for reported output size apparently not big enough.", e);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new IllegalStateException("Unexpected exception during GCM decryption.", e);
		}
	}

	// the spec mixes the block number into the AAD as an unsigned 32 bit big-endian integer
	private static byte[] chunkNumberBigEndian(long chunkNumber) {
		assert chunkNumber >= 0 && chunkNumber <= 0xFFFFFFFFL;
		return ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.BIG_ENDIAN).putInt((int) chunkNumber).array();
	}

}
