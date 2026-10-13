package org.cryptomator.cryptolib.uvf;

import java.nio.charset.StandardCharsets;

/**
 * Well-known names, sizes and identifiers of the Unified Vault Format.
 *
 * @see <a href="https://github.com/encryption-alliance/unified-vault-format">UVF specification</a>
 */
final class Constants {

	private Constants() {
	}

	static final int SPEC_VERSION = 1;
	static final String CONFIG_FILE_NAME = "vault.uvf";
	static final String SPEC_VERSION_HEADER = "uvf.spec.version";
	static final String CONTENT_TYPE = "json";

	static final String FILE_FORMAT = "AES-256-GCM-32k";
	static final String NAME_FORMAT = "AES-SIV-512-B64URL";
	static final String KDF = "HKDF-SHA512";
	static final int SEED_ID_LEN = Integer.BYTES;
	static final int SEED_LEN = 32;
	static final int KDF_SALT_LEN = 32;
	static final int DIR_ID_LEN = 32;

	static final String DATA_DIR_NAME = "d";
	static final String FILE_EXT = ".uvf";
	static final String DIR_FILE_NAME = "dir.uvf";
	static final String SYMLINK_FILE_NAME = "symlink.uvf";

	static final byte[] KDF_CONTEXT_FILE_HEADER = "fileHeader".getBytes(StandardCharsets.US_ASCII);
	static final byte[] KDF_CONTEXT_SIV = "siv".getBytes(StandardCharsets.US_ASCII);
	static final byte[] KDF_CONTEXT_HMAC = "hmac".getBytes(StandardCharsets.US_ASCII);
	static final byte[] KDF_CONTEXT_ROOT_DIR_ID = "rootDirId".getBytes(StandardCharsets.US_ASCII);

	static final String CONTENT_ENC_ALG = "AES";
	static final byte[] MAGIC_BYTES = {'u', 'v', 'f', 0x00}; // 3 byte signature + 1 byte spec version
	static final int GENERAL_HEADER_LEN = MAGIC_BYTES.length + SEED_ID_LEN; // 8
	static final int GCM_NONCE_SIZE = 12;
	static final int GCM_TAG_SIZE = 16;
	static final int HEADER_CONTENT_KEY_LEN = 32;
	static final int HEADER_SIZE = GENERAL_HEADER_LEN + GCM_NONCE_SIZE + HEADER_CONTENT_KEY_LEN + GCM_TAG_SIZE; // 68
	static final int CHUNK_SIZE = 32 * 1024; // 32768
	static final int PAYLOAD_SIZE = CHUNK_SIZE - GCM_NONCE_SIZE - GCM_TAG_SIZE; // 32740
	static final long MAX_CHUNK_INDEX = 0xFFFFFFFFL; // the chunk index is a 32 bit unsigned integer

}
