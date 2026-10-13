package org.cryptomator.cryptolib.cvf8;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.CvfMasterkey;
import org.cryptomator.cryptolib.common.CipherSupplier;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;
import org.cryptomator.cryptolib.common.MacSupplier;
import org.cryptomator.cryptolib.common.ObjectPool;
import org.cryptomator.cryptolib.internal.FileHeaderParts;
import org.cryptomator.cryptolib.internal.FileLayout;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.cryptomator.cryptolib.cvf8.Constants.CONTENT_ENC_ALG;
import static org.cryptomator.cryptolib.cvf8.Constants.CTRMAC_CHUNK_SIZE;
import static org.cryptomator.cryptolib.cvf8.Constants.CTRMAC_MAC_SIZE;
import static org.cryptomator.cryptolib.cvf8.Constants.CTRMAC_NONCE_SIZE;
import static org.cryptomator.cryptolib.cvf8.Constants.HEADER_CONTENT_KEY_LEN;
import static org.cryptomator.cryptolib.cvf8.Constants.HEADER_PAYLOAD_LEN;
import static org.cryptomator.cryptolib.cvf8.Constants.HEADER_RESERVED_VALUE;
import static org.cryptomator.cryptolib.cvf8.Constants.PAYLOAD_SIZE;

/**
 * {@link org.cryptomator.cryptolib.api.CipherCombo#SIV_CTRMAC}: AES-CTR with HMAC-SHA256 for headers (88 bytes) and chunks (16 nonce + payload + 32 MAC).
 */
final class CtrMacCodec implements Cvf8ContentCodec {

	private static final int HEADER_NONCE_POS = 0;
	private static final int HEADER_PAYLOAD_POS = HEADER_NONCE_POS + CTRMAC_NONCE_SIZE; // 16
	private static final int HEADER_MAC_POS = HEADER_PAYLOAD_POS + HEADER_PAYLOAD_LEN; // 56
	private static final int HEADER_SIZE = HEADER_MAC_POS + CTRMAC_MAC_SIZE; // 88
	private static final FileLayout LAYOUT = new FileLayout(HEADER_SIZE, PAYLOAD_SIZE, CTRMAC_CHUNK_SIZE, false);

	private final CvfMasterkey masterkey;
	private final SecureRandom random;

	CtrMacCodec(CvfMasterkey masterkey, SecureRandom random) {
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
		byte[] nonce = new byte[CTRMAC_NONCE_SIZE];
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
		try (DestroyableSecretKey ek = masterkey.getEncKey(); DestroyableSecretKey mk = masterkey.getMacKey()) {
			ByteBuffer result = ByteBuffer.allocate(HEADER_SIZE);
			result.put(nonce);

			// encrypt payload:
			try (ObjectPool.Lease<Cipher> cipher = CipherSupplier.AES_CTR.encryptionCipher(ek, new IvParameterSpec(nonce))) {
				int encrypted = cipher.get().doFinal(payloadCleartext, result);
				assert encrypted == HEADER_PAYLOAD_LEN;
			}

			// mac nonce and ciphertext:
			ByteBuffer nonceAndCiphertext = result.duplicate();
			nonceAndCiphertext.flip();
			try (ObjectPool.Lease<Mac> mac = MacSupplier.HMAC_SHA256.keyed(mk)) {
				mac.get().update(nonceAndCiphertext);
				result.put(mac.get().doFinal());
			}

			result.flip();
			return result;
		} catch (ShortBufferException e) {
			throw new IllegalStateException("Result buffer too small for encrypted header payload.", e);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new IllegalStateException("Unexpected exception for CTR ciphers.", e);
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
		byte[] nonce = new byte[CTRMAC_NONCE_SIZE];
		buf.position(HEADER_NONCE_POS);
		buf.get(nonce);
		byte[] ciphertextPayload = new byte[HEADER_PAYLOAD_LEN];
		buf.position(HEADER_PAYLOAD_POS);
		buf.get(ciphertextPayload);
		byte[] expectedMac = new byte[CTRMAC_MAC_SIZE];
		buf.position(HEADER_MAC_POS);
		buf.get(expectedMac);

		// check mac:
		try (DestroyableSecretKey mk = masterkey.getMacKey(); ObjectPool.Lease<Mac> mac = MacSupplier.HMAC_SHA256.keyed(mk)) {
			ByteBuffer nonceAndCiphertext = buf.duplicate();
			nonceAndCiphertext.position(HEADER_NONCE_POS).limit(HEADER_NONCE_POS + CTRMAC_NONCE_SIZE + HEADER_PAYLOAD_LEN);
			mac.get().update(nonceAndCiphertext);
			byte[] calculatedMac = mac.get().doFinal();
			if (!MessageDigest.isEqual(expectedMac, calculatedMac)) {
				throw new AuthenticationFailedException("Header MAC doesn't match.");
			}
		}

		ByteBuffer payloadCleartext = ByteBuffer.allocate(HEADER_PAYLOAD_LEN);
		try (DestroyableSecretKey ek = masterkey.getEncKey()) {
			try (ObjectPool.Lease<Cipher> cipher = CipherSupplier.AES_CTR.decryptionCipher(ek, new IvParameterSpec(nonce))) {
				int decrypted = cipher.get().doFinal(ByteBuffer.wrap(ciphertextPayload), payloadCleartext);
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
		} catch (ShortBufferException e) {
			throw new IllegalStateException("Result buffer too small for decrypted header payload.", e);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new IllegalStateException("Unexpected exception for CTR ciphers.", e);
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
		if (ciphertextChunk.remaining() < cleartextChunk.remaining() + CTRMAC_NONCE_SIZE + CTRMAC_MAC_SIZE) {
			throw new IllegalArgumentException("Invalid ciphertext chunk size: " + ciphertextChunk.remaining() + ", must fit " + (cleartextChunk.remaining() + CTRMAC_NONCE_SIZE + CTRMAC_MAC_SIZE) + " bytes.");
		}
		try (DestroyableSecretKey fk = fileKey.copy()) {
			// nonce:
			byte[] nonce = new byte[CTRMAC_NONCE_SIZE];
			random.nextBytes(nonce);
			int start = ciphertextChunk.position();
			ciphertextChunk.put(nonce);

			// payload:
			try (ObjectPool.Lease<Cipher> cipher = CipherSupplier.AES_CTR.encryptionCipher(fk, new IvParameterSpec(nonce))) {
				cipher.get().doFinal(cleartextChunk, ciphertextChunk);
			}

			// mac:
			ByteBuffer nonceAndPayload = ciphertextChunk.duplicate();
			nonceAndPayload.position(start).limit(ciphertextChunk.position());
			byte[] authenticationCode = calcChunkMac(headerNonce, chunkIndex, nonceAndPayload);
			assert authenticationCode.length == CTRMAC_MAC_SIZE;
			ciphertextChunk.put(authenticationCode);
		} catch (ShortBufferException e) {
			throw new IllegalStateException("Buffer allocated for reported output size apparently not big enough.", e);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new IllegalStateException("Unexpected exception for CTR ciphers.", e);
		}
	}

	@Override
	public void decryptChunk(byte[] headerNonce, DestroyableSecretKey fileKey, ByteBuffer ciphertextChunk, ByteBuffer cleartextChunk, long chunkIndex) throws AuthenticationFailedException {
		if (ciphertextChunk.remaining() < CTRMAC_NONCE_SIZE + CTRMAC_MAC_SIZE || ciphertextChunk.remaining() > CTRMAC_CHUNK_SIZE) {
			throw new IllegalArgumentException("Invalid ciphertext chunk size: " + ciphertextChunk.remaining() + ", expected range [" + (CTRMAC_NONCE_SIZE + CTRMAC_MAC_SIZE) + ", " + CTRMAC_CHUNK_SIZE + "]");
		}
		if (cleartextChunk.remaining() < ciphertextChunk.remaining() - CTRMAC_NONCE_SIZE - CTRMAC_MAC_SIZE) {
			throw new IllegalArgumentException("Invalid cleartext chunk size: " + cleartextChunk.remaining() + ", must fit " + (ciphertextChunk.remaining() - CTRMAC_NONCE_SIZE - CTRMAC_MAC_SIZE) + " bytes.");
		}
		if (!checkChunkMac(headerNonce, chunkIndex, ciphertextChunk)) {
			throw new AuthenticationFailedException("Authentication of chunk " + chunkIndex + " failed.");
		}
		try (DestroyableSecretKey fk = fileKey.copy()) {
			// nonce:
			byte[] nonce = new byte[CTRMAC_NONCE_SIZE];
			ciphertextChunk.get(nonce, 0, CTRMAC_NONCE_SIZE);

			// payload:
			ByteBuffer payload = ciphertextChunk.duplicate();
			payload.limit(ciphertextChunk.limit() - CTRMAC_MAC_SIZE);
			try (ObjectPool.Lease<Cipher> cipher = CipherSupplier.AES_CTR.decryptionCipher(fk, new IvParameterSpec(nonce))) {
				cipher.get().doFinal(payload, cleartextChunk);
			}
			ciphertextChunk.position(ciphertextChunk.limit());
		} catch (ShortBufferException e) {
			throw new IllegalStateException("Buffer allocated for reported output size apparently not big enough.", e);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new IllegalStateException("Unexpected exception for CTR ciphers.", e);
		}
	}

	// visible for testing
	boolean checkChunkMac(byte[] headerNonce, long chunkIndex, ByteBuffer chunk) {
		assert chunk.remaining() >= CTRMAC_NONCE_SIZE + CTRMAC_MAC_SIZE;
		ByteBuffer nonceAndPayload = chunk.duplicate();
		nonceAndPayload.limit(chunk.limit() - CTRMAC_MAC_SIZE);
		ByteBuffer expectedMacBuf = chunk.duplicate();
		expectedMacBuf.position(chunk.limit() - CTRMAC_MAC_SIZE);
		byte[] expectedMac = new byte[CTRMAC_MAC_SIZE];
		expectedMacBuf.get(expectedMac);
		byte[] calculatedMac = calcChunkMac(headerNonce, chunkIndex, nonceAndPayload);
		return MessageDigest.isEqual(expectedMac, calculatedMac);
	}

	private byte[] calcChunkMac(byte[] headerNonce, long chunkIndex, ByteBuffer nonceAndCiphertext) {
		try (DestroyableSecretKey mk = masterkey.getMacKey(); ObjectPool.Lease<Mac> mac = MacSupplier.HMAC_SHA256.keyed(mk)) {
			byte[] chunkIndexBigEndian = ByteBuffer.allocate(Long.BYTES).order(ByteOrder.BIG_ENDIAN).putLong(chunkIndex).array();
			mac.get().update(headerNonce);
			mac.get().update(chunkIndexBigEndian);
			mac.get().update(nonceAndCiphertext);
			return mac.get().doFinal();
		}
	}

}
