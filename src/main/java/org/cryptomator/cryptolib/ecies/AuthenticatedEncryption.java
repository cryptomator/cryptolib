package org.cryptomator.cryptolib.ecies;

import javax.crypto.AEADBadTagException;

public interface AuthenticatedEncryption {

	/**
	 * AES-GCM with a 96 bit nonce taken from a the shared secret.
	 *
	 * Since the secret is derived via ECDH with an ephemeral key, the nonce is guaranteed to be unique.
	 */
	AuthenticatedEncryption GCM_WITH_SECRET_NONCE = new GcmWithSecretNonce();

	/**
	 * @return number of bytes required during {@link #encrypt(byte[], byte[])} and {@link #decrypt(byte[], byte[])}
	 */
	int requiredSecretBytes();

	/**
	 * Encrypts the given <code>plaintext</code>
	 *
	 * @param secret    secret data required for encryption, such as (but not limited to) a key
	 * @param plaintext The data to encrypt
	 * @return The encrypted data, including all required information for authentication, such as a tag
	 */
	byte[] encrypt(byte[] secret, byte[] plaintext);

	/**
	 * Encrypts the given <code>ciphertext</code>
	 *
	 * @param secret     secret data required for encryption, such as (but not limited to) a key
	 * @param ciphertext The data to decrypt
	 * @return The decrypted data
	 * @throws AEADBadTagException In case of an authentication failure (including wrong <code>secret</code>)
	 */
	byte[] decrypt(byte[] secret, byte[] ciphertext) throws AEADBadTagException;
}
