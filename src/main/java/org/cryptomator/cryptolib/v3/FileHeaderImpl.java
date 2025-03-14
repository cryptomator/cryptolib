package org.cryptomator.cryptolib.v3;

import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;

import javax.security.auth.Destroyable;

class FileHeaderImpl implements FileHeader, Destroyable {

	static final int UVF_GENERAL_HEADERS_LEN = Constants.UVF_MAGIC_BYTES.length + Integer.BYTES;
	static final int NONCE_POS = 8;
	static final int NONCE_LEN = Constants.GCM_NONCE_SIZE;
	static final int CONTENT_KEY_POS = NONCE_POS + NONCE_LEN; // 20
	static final int CONTENT_KEY_LEN = 32;
	static final int TAG_POS = CONTENT_KEY_POS + CONTENT_KEY_LEN; // 52
	static final int TAG_LEN = Constants.GCM_TAG_SIZE;
	static final int SIZE = UVF_GENERAL_HEADERS_LEN + NONCE_LEN + CONTENT_KEY_LEN + TAG_LEN;

	private final int seedId;
	private final byte[] nonce;
	private final DestroyableSecretKey contentKey;

	FileHeaderImpl(int seedId, byte[] nonce, DestroyableSecretKey contentKey) {
		if (nonce.length != NONCE_LEN) {
			throw new IllegalArgumentException("Invalid nonce length. (was: " + nonce.length + ", required: " + NONCE_LEN + ")");
		}
		this.seedId = seedId;
		this.nonce = nonce;
		this.contentKey = contentKey;
	}

	static FileHeaderImpl cast(FileHeader header) {
		if (header instanceof FileHeaderImpl) {
			return (FileHeaderImpl) header;
		} else {
			throw new IllegalArgumentException("Unsupported header type " + header.getClass());
		}
	}
	
	public int getSeedId() {
		return seedId;
	}

	public byte[] getNonce() {
		return nonce;
	}

	public DestroyableSecretKey getContentKey() {
		return contentKey;
	}

	@Override
	public long getReserved() {
		return 0;
	}

	@Override
	public void setReserved(long reserved) {
		/* noop */
	}

	@Override
	public boolean isDestroyed() {
		return contentKey.isDestroyed();
	}

	@Override
	public void destroy() {
		contentKey.destroy();
	}

}
