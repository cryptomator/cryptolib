package org.cryptomator.cryptolib.uvf;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.common.CipherSupplier;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;
import org.cryptomator.cryptolib.internal.ChunkCodec;
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

import static org.cryptomator.cryptolib.uvf.Constants.CHUNK_SIZE;
import static org.cryptomator.cryptolib.uvf.Constants.CONTENT_ENC_ALG;
import static org.cryptomator.cryptolib.uvf.Constants.GCM_NONCE_SIZE;
import static org.cryptomator.cryptolib.uvf.Constants.GCM_TAG_SIZE;
import static org.cryptomator.cryptolib.uvf.Constants.GENERAL_HEADER_LEN;
import static org.cryptomator.cryptolib.uvf.Constants.HEADER_CONTENT_KEY_LEN;
import static org.cryptomator.cryptolib.uvf.Constants.HEADER_SIZE;
import static org.cryptomator.cryptolib.uvf.Constants.MAGIC_BYTES;
import static org.cryptomator.cryptolib.uvf.Constants.MAX_CHUNK_INDEX;
import static org.cryptomator.cryptolib.uvf.Constants.PAYLOAD_SIZE;

/**
 * UVF file format {@code AES-256-GCM-32k}: header = magic ‖ seed id ‖ nonce ‖ AES-GCM(file key) ‖ tag (68 bytes), chunks = nonce ‖ AES-GCM(payload ≤ 32740) ‖ tag (≤ 32768 bytes).
 *
 * @see <a href="https://github.com/encryption-alliance/unified-vault-format/blob/develop/file%20content%20encryption/AES-256-GCM.md">AES-256-GCM file content encryption</a>
 */
final class UvfContentCodec implements ChunkCodec {

	static final FileLayout LAYOUT = new FileLayout(HEADER_SIZE, PAYLOAD_SIZE, CHUNK_SIZE, true);
	private static final int NONCE_POS = GENERAL_HEADER_LEN; // 8
	private static final int CONTENT_KEY_POS = NONCE_POS + GCM_NONCE_SIZE; // 20

	private final UvfSeeds seeds;
	private final SecureRandom random;

	UvfContentCodec(UvfSeeds seeds, SecureRandom random) {
		this.seeds = seeds;
		this.random = random;
	}

	// HEADER

	/**
	 * @param seedId The seed to derive the header key from; becomes part of the general header
	 * @return A fresh, already encrypted header with a random nonce and content key
	 */
	FileHeaderParts createHeader(int seedId) {
		byte[] nonce = new byte[GCM_NONCE_SIZE];
		random.nextBytes(nonce);
		byte[] contentKey = new byte[HEADER_CONTENT_KEY_LEN];
		random.nextBytes(contentKey);
		try (DestroyableSecretKey headerKey = seeds.subKey(seedId, 32, Constants.KDF_CONTEXT_FILE_HEADER, CONTENT_ENC_ALG)) {
			ByteBuffer result = ByteBuffer.allocate(HEADER_SIZE);
			result.put(MAGIC_BYTES);
			result.order(ByteOrder.BIG_ENDIAN).putInt(seedId);
			ByteBuffer generalHeader = result.duplicate();
			generalHeader.position(0).limit(GENERAL_HEADER_LEN);
			result.put(nonce);
			Cipher cipher = CipherSupplier.AES_GCM.encryptionCipher(headerKey, new GCMParameterSpec(GCM_TAG_SIZE * Byte.SIZE, nonce));
			cipher.updateAAD(generalHeader);
			int encrypted = cipher.doFinal(ByteBuffer.wrap(contentKey), result);
			assert encrypted == HEADER_CONTENT_KEY_LEN + GCM_TAG_SIZE;
			result.flip();
			return new FileHeaderParts(result, nonce, new DestroyableSecretKey(contentKey, CONTENT_ENC_ALG), seedId);
		} catch (ShortBufferException e) {
			throw new IllegalStateException("Result buffer too small for encrypted header payload.", e);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new IllegalStateException("Unexpected exception during GCM encryption.", e);
		} finally {
			Arrays.fill(contentKey, (byte) 0x00);
		}
	}

	/**
	 * @param encryptedHeader The encrypted header, position to limit
	 * @return The decrypted header
	 * @throws AuthenticationFailedException If the header is unauthentic
	 * @throws IllegalArgumentException If the header is malformed or refers to an unknown seed
	 */
	FileHeaderParts decryptHeader(ByteBuffer encryptedHeader) throws AuthenticationFailedException {
		if (encryptedHeader.remaining() < HEADER_SIZE) {
			throw new IllegalArgumentException("Malformed ciphertext header");
		}
		ByteBuffer buf = encryptedHeader.slice();
		buf.limit(HEADER_SIZE);
		byte[] magic = new byte[MAGIC_BYTES.length];
		buf.get(magic);
		if (!Arrays.equals(MAGIC_BYTES, magic)) {
			throw new IllegalArgumentException("Not a UVF file of spec version " + MAGIC_BYTES[3]);
		}
		int seedId = buf.order(ByteOrder.BIG_ENDIAN).getInt();
		ByteBuffer generalHeader = buf.duplicate();
		generalHeader.position(0).limit(GENERAL_HEADER_LEN);
		byte[] nonce = new byte[GCM_NONCE_SIZE];
		buf.position(NONCE_POS);
		buf.get(nonce);
		byte[] ciphertextAndTag = new byte[HEADER_CONTENT_KEY_LEN + GCM_TAG_SIZE];
		buf.position(CONTENT_KEY_POS);
		buf.get(ciphertextAndTag);

		// HEADER_CONTENT_KEY_LEN + GCM_TAG_SIZE is required to fix a bug in Android API level pre 29, see https://issuetracker.google.com/issues/197534888 and #24
		ByteBuffer contentKeyBuf = ByteBuffer.allocate(HEADER_CONTENT_KEY_LEN + GCM_TAG_SIZE);
		try (DestroyableSecretKey headerKey = seeds.subKey(seedId, 32, Constants.KDF_CONTEXT_FILE_HEADER, CONTENT_ENC_ALG)) {
			Cipher cipher = CipherSupplier.AES_GCM.decryptionCipher(headerKey, new GCMParameterSpec(GCM_TAG_SIZE * Byte.SIZE, nonce));
			cipher.updateAAD(generalHeader);
			int decrypted = cipher.doFinal(ByteBuffer.wrap(ciphertextAndTag), contentKeyBuf);
			assert decrypted == HEADER_CONTENT_KEY_LEN;
			contentKeyBuf.flip();
			byte[] contentKey = new byte[HEADER_CONTENT_KEY_LEN];
			contentKeyBuf.get(contentKey);
			try {
				ByteBuffer copy = ByteBuffer.allocate(HEADER_SIZE);
				buf.rewind();
				copy.put(buf);
				copy.flip();
				return new FileHeaderParts(copy, nonce, new DestroyableSecretKey(contentKey, CONTENT_ENC_ALG), seedId);
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
			Arrays.fill(contentKeyBuf.array(), (byte) 0x00);
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
		checkChunkIndex(chunkIndex);
		try (DestroyableSecretKey fk = fileKey.copy()) {
			byte[] nonce = new byte[GCM_NONCE_SIZE];
			random.nextBytes(nonce);
			Cipher cipher = CipherSupplier.AES_GCM.encryptionCipher(fk, new GCMParameterSpec(GCM_TAG_SIZE * Byte.SIZE, nonce));
			cipher.updateAAD(chunkIndexBigEndian(chunkIndex));
			cipher.updateAAD(headerNonce);
			ciphertextChunk.put(nonce);
			cipher.doFinal(cleartextChunk, ciphertextChunk);
		} catch (ShortBufferException e) {
			throw new IllegalStateException("Buffer allocated for reported output size apparently not big enough.", e);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new IllegalStateException("Unexpected exception during GCM encryption.", e);
		}
	}

	@Override
	public void decryptChunk(byte[] headerNonce, DestroyableSecretKey fileKey, ByteBuffer ciphertextChunk, ByteBuffer cleartextChunk, long chunkIndex) throws AuthenticationFailedException {
		if (ciphertextChunk.remaining() < GCM_NONCE_SIZE + GCM_TAG_SIZE || ciphertextChunk.remaining() > CHUNK_SIZE) {
			throw new IllegalArgumentException("Invalid ciphertext chunk size: " + ciphertextChunk.remaining() + ", expected range [" + (GCM_NONCE_SIZE + GCM_TAG_SIZE) + ", " + CHUNK_SIZE + "]");
		}
		if (cleartextChunk.remaining() < ciphertextChunk.remaining() - GCM_NONCE_SIZE - GCM_TAG_SIZE) {
			throw new IllegalArgumentException("Invalid cleartext chunk size: " + cleartextChunk.remaining() + ", must fit " + (ciphertextChunk.remaining() - GCM_NONCE_SIZE - GCM_TAG_SIZE) + " bytes.");
		}
		checkChunkIndex(chunkIndex);
		try (DestroyableSecretKey fk = fileKey.copy()) {
			byte[] nonce = new byte[GCM_NONCE_SIZE];
			ciphertextChunk.get(nonce, 0, GCM_NONCE_SIZE);
			Cipher cipher = CipherSupplier.AES_GCM.decryptionCipher(fk, new GCMParameterSpec(GCM_TAG_SIZE * Byte.SIZE, nonce));
			cipher.updateAAD(chunkIndexBigEndian(chunkIndex));
			cipher.updateAAD(headerNonce);
			cipher.doFinal(ciphertextChunk, cleartextChunk);
		} catch (AEADBadTagException e) {
			throw new AuthenticationFailedException("Content tag mismatch.", e);
		} catch (ShortBufferException e) {
			throw new IllegalStateException("Buffer allocated for reported output size apparently not big enough.", e);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new IllegalStateException("Unexpected exception during GCM decryption.", e);
		}
	}

	private static void checkChunkIndex(long chunkIndex) {
		if (chunkIndex < 0 || chunkIndex > MAX_CHUNK_INDEX) {
			throw new IllegalArgumentException("Invalid chunk index: " + chunkIndex + ", expected range [0, " + MAX_CHUNK_INDEX + "]");
		}
	}

	// the block index is a 32 bit big endian unsigned integer
	private static byte[] chunkIndexBigEndian(long chunkIndex) {
		return ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.BIG_ENDIAN).putInt((int) chunkIndex).array();
	}

}
