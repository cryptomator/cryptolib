package org.cryptomator.cryptolib.v1;

final class Constants {

	private Constants() {
	}

	static final String C9R_FILE_EXT = ".c9r";

	static final String CONTENT_ENC_ALG = "AES";

	static final int NONCE_SIZE = 16;
	static final int PAYLOAD_SIZE = 32 * 1024;
	static final int MAC_SIZE = 32;
	static final int CHUNK_SIZE = NONCE_SIZE + PAYLOAD_SIZE + MAC_SIZE;

}
