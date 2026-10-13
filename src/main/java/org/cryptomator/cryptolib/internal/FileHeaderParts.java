package org.cryptomator.cryptolib.internal;

import org.cryptomator.cryptolib.common.DestroyableSecretKey;

import java.nio.ByteBuffer;

/**
 * The pieces of a created or decrypted file header that a {@link VaultFileImpl} needs.
 */
public final class FileHeaderParts {

	private final ByteBuffer encrypted;
	private final byte[] nonce;
	private final DestroyableSecretKey fileKey;
	private final int seedId;

	/**
	 * @param encrypted The complete encrypted header, position 0, limit at its end
	 * @param nonce The header nonce (bound into every chunk's authentication)
	 * @param fileKey The content key; ownership passes to the file
	 * @param seedId Key revision the header was encrypted with, {@code 0} if not applicable
	 */
	public FileHeaderParts(ByteBuffer encrypted, byte[] nonce, DestroyableSecretKey fileKey, int seedId) {
		this.encrypted = encrypted;
		this.nonce = nonce;
		this.fileKey = fileKey;
		this.seedId = seedId;
	}

	public ByteBuffer encrypted() {
		return encrypted;
	}

	public byte[] nonce() {
		return nonce;
	}

	public DestroyableSecretKey fileKey() {
		return fileKey;
	}

	public int seedId() {
		return seedId;
	}

}
