package org.cryptomator.cryptolib.v3;

final class Constants {

	private Constants() {
	}

	static final String UVF_FILE_EXT = ".uvf";

	static final String CONTENT_ENC_ALG = "AES";

	static final byte[] UVF_MAGIC_BYTES = new byte[]{'u', 'v', 'f', 0x00}; // TODO increase version number when adopting final spec

	static final int GCM_NONCE_SIZE = 12; // 96 bit IVs strongly recommended for GCM
	static final int PAYLOAD_SIZE = 32 * 1024;
	static final int GCM_TAG_SIZE = 16;
	static final int CHUNK_SIZE = GCM_NONCE_SIZE + PAYLOAD_SIZE + GCM_TAG_SIZE;

}
