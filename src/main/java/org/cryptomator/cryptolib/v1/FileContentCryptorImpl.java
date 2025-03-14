package org.cryptomator.cryptolib.v1;

import org.cryptomator.cryptolib.api.*;
import org.cryptomator.cryptolib.common.CipherSupplier;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;
import org.cryptomator.cryptolib.common.MacSupplier;
import org.cryptomator.cryptolib.common.ObjectPool;

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

import static org.cryptomator.cryptolib.v1.Constants.CHUNK_SIZE;
import static org.cryptomator.cryptolib.v1.Constants.MAC_SIZE;
import static org.cryptomator.cryptolib.v1.Constants.NONCE_SIZE;
import static org.cryptomator.cryptolib.v1.Constants.PAYLOAD_SIZE;

class FileContentCryptorImpl implements FileContentCryptor {

	private final PerpetualMasterkey masterkey;
	private final SecureRandom random;

	FileContentCryptorImpl(PerpetualMasterkey masterkey, SecureRandom random) {
		this.masterkey = masterkey;
		this.random = random;
	}

	@Override
	public boolean canSkipAuthentication() {
		return true;
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
	public ByteBuffer encryptChunk(ByteBuffer cleartextChunk, long chunkNumber, FileHeader header) {
		ByteBuffer ciphertextChunk = ByteBuffer.allocate(CHUNK_SIZE);
		encryptChunk(cleartextChunk, ciphertextChunk, chunkNumber, header);
		ciphertextChunk.flip();
		return ciphertextChunk;
	}

	@Override
	public void encryptChunk(ByteBuffer cleartextChunk, ByteBuffer ciphertextChunk, long chunkNumber, FileHeader header) {
		if (cleartextChunk.remaining() < 0 || cleartextChunk.remaining() > PAYLOAD_SIZE) {
			throw new IllegalArgumentException("Invalid cleartext chunk size: " + cleartextChunk.remaining() + ", expected range [1, " + PAYLOAD_SIZE + "]");
		}
		if (ciphertextChunk.remaining() < CHUNK_SIZE) {
			throw new IllegalArgumentException("Invalid cipehrtext chunk size: " + ciphertextChunk.remaining() + ", must fit up to " + CHUNK_SIZE + " bytes.");
		}
		FileHeaderImpl headerImpl = FileHeaderImpl.cast(header);
		encryptChunk(cleartextChunk, ciphertextChunk, chunkNumber, headerImpl.getNonce(), headerImpl.getPayload().getContentKey());
	}

	@Override
	public ByteBuffer decryptChunk(ByteBuffer ciphertextChunk, long chunkNumber, FileHeader header, boolean authenticate) throws AuthenticationFailedException {
		ByteBuffer cleartextChunk = ByteBuffer.allocate(PAYLOAD_SIZE);
		decryptChunk(ciphertextChunk, cleartextChunk, chunkNumber, header, authenticate);
		cleartextChunk.flip();
		return cleartextChunk;
	}

	@Override
	public void decryptChunk(ByteBuffer ciphertextChunk, ByteBuffer cleartextChunk, long chunkNumber, FileHeader header, boolean authenticate) throws AuthenticationFailedException {
		if (ciphertextChunk.remaining() < NONCE_SIZE + MAC_SIZE || ciphertextChunk.remaining() > CHUNK_SIZE) {
			throw new IllegalArgumentException("Invalid ciphertext chunk size: " + ciphertextChunk.remaining() + ", expected range [" + (NONCE_SIZE + MAC_SIZE) + ", " + CHUNK_SIZE + "]");
		}
		if (cleartextChunk.remaining() < Constants.PAYLOAD_SIZE) {
			throw new IllegalArgumentException("Invalid cleartext chunk size: " + cleartextChunk.remaining() + ", must fit up to " + PAYLOAD_SIZE + " bytes.");
		}
		FileHeaderImpl headerImpl = FileHeaderImpl.cast(header);
		if (authenticate && !checkChunkMac(headerImpl.getNonce(), chunkNumber, ciphertextChunk)) {
			throw new AuthenticationFailedException("Authentication of chunk " + chunkNumber + " failed.");
		} else {
			decryptChunk(ciphertextChunk, cleartextChunk, headerImpl.getPayload().getContentKey());
		}
	}

	// visible for testing
	void encryptChunk(ByteBuffer cleartextChunk, ByteBuffer ciphertextChunk, long chunkNumber, byte[] headerNonce, DestroyableSecretKey fileKey) {
		try (DestroyableSecretKey fk = fileKey.copy()) {
			// nonce:
			byte[] nonce = new byte[NONCE_SIZE];
			random.nextBytes(nonce);
			ciphertextChunk.put(nonce);

			// payload:
			try (ObjectPool.Lease<Cipher> cipher = CipherSupplier.AES_CTR.encryptionCipher(fk, new IvParameterSpec(nonce))) {
				assert ciphertextChunk.remaining() >= cipher.get().getOutputSize(cleartextChunk.remaining()) + MAC_SIZE;
				cipher.get().doFinal(cleartextChunk, ciphertextChunk);
			}

			// mac:
			ByteBuffer nonceAndPayload = ciphertextChunk.duplicate();
			nonceAndPayload.flip();
			byte[] authenticationCode = calcChunkMac(headerNonce, chunkNumber, nonceAndPayload);
			assert authenticationCode.length == MAC_SIZE;
			ciphertextChunk.put(authenticationCode);
		} catch (ShortBufferException e) {
			throw new IllegalStateException("Buffer allocated for reported output size apparently not big enough.", e);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new IllegalStateException("Unexpected exception for CTR ciphers.", e);
		}
	}

	// visible for testing
	void decryptChunk(ByteBuffer ciphertextChunk, ByteBuffer cleartextChunk, DestroyableSecretKey fileKey) {
		assert ciphertextChunk.remaining() >= NONCE_SIZE + MAC_SIZE;

		try (DestroyableSecretKey fk = fileKey.copy()) {
			// nonce:
			final byte[] nonce = new byte[NONCE_SIZE];
			ciphertextChunk.get(nonce, 0, NONCE_SIZE);

			// payload:
			final ByteBuffer payloadBuf = ciphertextChunk.duplicate();
			payloadBuf.limit(ciphertextChunk.limit() - MAC_SIZE);

			// payload:
			try (ObjectPool.Lease<Cipher> cipher = CipherSupplier.AES_CTR.decryptionCipher(fk, new IvParameterSpec(nonce))) {
				assert cleartextChunk.remaining() >= cipher.get().getOutputSize(payloadBuf.remaining());
				cipher.get().doFinal(payloadBuf, cleartextChunk);
			}
		} catch (ShortBufferException e) {
			throw new IllegalStateException("Buffer allocated for reported output size apparently not big enough.", e);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new IllegalStateException("Unexpected exception for CTR ciphers.", e);
		}
	}

	// visible for testing
	boolean checkChunkMac(byte[] headerNonce, long chunkNumber, ByteBuffer chunkBuf) {
		assert chunkBuf.remaining() >= NONCE_SIZE + MAC_SIZE;

		// get nonce + payload
		final ByteBuffer nonceAndPayload = chunkBuf.duplicate();
		nonceAndPayload.limit(chunkBuf.limit() - MAC_SIZE);
		final ByteBuffer expectedMacBuf = chunkBuf.duplicate();
		expectedMacBuf.position(chunkBuf.limit() - MAC_SIZE);

		// get expected MAC:
		final byte[] expectedMac = new byte[MAC_SIZE];
		expectedMacBuf.get(expectedMac);

		// get actual MAC:
		final byte[] calculatedMac = calcChunkMac(headerNonce, chunkNumber, nonceAndPayload);

		// time-constant equality check of two MACs:
		return MessageDigest.isEqual(expectedMac, calculatedMac);
	}

	private byte[] calcChunkMac(byte[] headerNonce, long chunkNumber, ByteBuffer nonceAndCiphertext) {
		try (DestroyableSecretKey mk = masterkey.getMacKey();
			 ObjectPool.Lease<Mac> mac = MacSupplier.HMAC_SHA256.keyed(mk)) {
			final byte[] chunkNumberBigEndian = ByteBuffer.allocate(Long.SIZE / Byte.SIZE).order(ByteOrder.BIG_ENDIAN).putLong(chunkNumber).array();
			mac.get().update(headerNonce);
			mac.get().update(chunkNumberBigEndian);
			mac.get().update(nonceAndCiphertext);
			return mac.get().doFinal();
		}
	}

}
