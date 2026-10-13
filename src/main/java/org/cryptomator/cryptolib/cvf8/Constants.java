package org.cryptomator.cryptolib.cvf8;

import java.net.URI;

/**
 * Well-known names and sizes of Cryptomator Vault Format 8.
 */
final class Constants {

	private Constants() {
	}

	static final int VAULT_VERSION = 8;
	static final String CONFIG_FILE_NAME = "vault.cryptomator";
	static final URI DEFAULT_KEY_ID = URI.create("masterkeyfile:masterkey.cryptomator");

	static final String DATA_DIR_NAME = "d";
	static final String ROOT_DIR_ID = "";
	static final int MAX_DIR_ID_LENGTH = 1000;

	static final String FILE_EXT = ".c9r";
	static final String SHORTENED_FILE_EXT = ".c9s";
	static final String DIR_FILE_NAME = "dir.c9r";
	static final String SYMLINK_FILE_NAME = "symlink.c9r";
	static final String CONTENTS_FILE_NAME = "contents.c9r";
	static final String INFLATED_NAME_FILE_NAME = "name.c9s";
	static final String DIR_ID_BACKUP_FILE_NAME = "dirid.c9r";

	static final String CONTENT_ENC_ALG = "AES";
	static final int PAYLOAD_SIZE = 32 * 1024;

	static final int CTRMAC_NONCE_SIZE = 16;
	static final int CTRMAC_MAC_SIZE = 32;
	static final int CTRMAC_CHUNK_SIZE = CTRMAC_NONCE_SIZE + PAYLOAD_SIZE + CTRMAC_MAC_SIZE;

	static final int GCM_NONCE_SIZE = 12; // 96 bit IVs strongly recommended for GCM
	static final int GCM_TAG_SIZE = 16;
	static final int GCM_CHUNK_SIZE = GCM_NONCE_SIZE + PAYLOAD_SIZE + GCM_TAG_SIZE;

	static final int HEADER_RESERVED_LEN = Long.BYTES;
	static final int HEADER_CONTENT_KEY_LEN = 32;
	static final int HEADER_PAYLOAD_LEN = HEADER_RESERVED_LEN + HEADER_CONTENT_KEY_LEN;
	static final long HEADER_RESERVED_VALUE = -1L; // formerly the cleartext file size, now all 0xFF

}
