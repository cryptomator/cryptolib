package org.cryptomator.cryptolib.ecies;

import com.google.common.base.Throwables;
import org.cryptomator.cryptolib.common.CipherSupplier;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;
import org.cryptomator.cryptolib.common.ObjectPool;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.GCMParameterSpec;
import java.util.Arrays;

class GcmWithSecretNonce implements AuthenticatedEncryption {

	private static final int GCM_KEY_SIZE = 32;
	private static final int GCM_TAG_SIZE = 16;
	private static final int GCM_NONCE_SIZE = 12; // 96 bit IVs strongly recommended for GCM

	@Override
	public int requiredSecretBytes() {
		return GCM_KEY_SIZE + GCM_NONCE_SIZE;
	}

	@Override
	public byte[] encrypt(byte[] secret, byte[] plaintext) {
		try (DestroyableSecretKey key = new DestroyableSecretKey(secret, 0, GCM_KEY_SIZE, "AES")) {
			byte[] nonce = Arrays.copyOfRange(secret, GCM_KEY_SIZE, GCM_KEY_SIZE + GCM_NONCE_SIZE);
			try (ObjectPool.Lease<Cipher> cipher = CipherSupplier.AES_GCM.encryptionCipher(key, new GCMParameterSpec(GCM_TAG_SIZE * Byte.SIZE, nonce))) {
				return cipher.get().doFinal(plaintext);
			}
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new IllegalStateException("Unexpected exception during GCM decryption.", e);
		}
	}

	@Override
	public byte[] decrypt(byte[] secret, byte[] ciphertext) throws AEADBadTagException {
		try (DestroyableSecretKey key = new DestroyableSecretKey(secret, 0, GCM_KEY_SIZE, "AES")) {
			byte[] nonce = Arrays.copyOfRange(secret, GCM_KEY_SIZE, GCM_KEY_SIZE + GCM_NONCE_SIZE);
			try (ObjectPool.Lease<Cipher> cipher = CipherSupplier.AES_GCM.decryptionCipher(key, new GCMParameterSpec(GCM_TAG_SIZE * Byte.SIZE, nonce))) {
				return cipher.get().doFinal(ciphertext);
			}
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			Throwables.throwIfInstanceOf(e, AEADBadTagException.class);
			throw new IllegalStateException("Unexpected exception during GCM decryption.", e);
		}
	}
}
