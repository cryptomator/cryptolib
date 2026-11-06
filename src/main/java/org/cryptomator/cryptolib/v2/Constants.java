package org.cryptomator.cryptolib.v2;

final class Constants {

	private Constants() {
	}

	static final String C9R_FILE_EXT = ".c9r";

	static final String CONTENT_ENC_ALG = "AES";

	static final int GCM_NONCE_SIZE = 12; // 96 bit IVs strongly recommended for GCM
	static final int PAYLOAD_SIZE = 32 * 1024;
	static final int GCM_TAG_SIZE = 16;
	static final int CHUNK_SIZE = GCM_NONCE_SIZE + PAYLOAD_SIZE + GCM_TAG_SIZE;

}
