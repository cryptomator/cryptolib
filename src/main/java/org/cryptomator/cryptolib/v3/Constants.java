package org.cryptomator.cryptolib.v3;

import java.nio.charset.StandardCharsets;

final class Constants {

	private Constants() {
	}

	static final String UVF_FILE_EXT = ".uvf";

	static final String CONTENT_ENC_ALG = "AES";

	static final byte UVF_SPEC_VERSION = 1;
	static final byte[] UVF_MAGIC = new byte[]{'u', 'v', 'f'};
	static final byte[] UVF_MAGIC_BYTES = new byte[]{'u', 'v', 'f', UVF_SPEC_VERSION}; // magic + spec version, i.e. the first 4 of the 8 general header bytes

	// KDF contexts of the header key, one per node type (see "General requirements" of the file content encryption spec):
	static final byte[] KDF_CONTEXT_FILE_HEADER = "fileHeader".getBytes(StandardCharsets.US_ASCII);
	static final byte[] KDF_CONTEXT_DIR_HEADER = "dirHeader".getBytes(StandardCharsets.US_ASCII);
	static final byte[] KDF_CONTEXT_SYMLINK_HEADER = "symlinkHeader".getBytes(StandardCharsets.US_ASCII);

	static final int DIR_ID_LEN = 32;

	static final int GCM_NONCE_SIZE = 12; // 96 bit IVs strongly recommended for GCM
	static final int PAYLOAD_SIZE = 32740; // AES-256-GCM-32k: 32768 byte chunks minus nonce and tag
	static final int GCM_TAG_SIZE = 16;
	static final int CHUNK_SIZE = GCM_NONCE_SIZE + PAYLOAD_SIZE + GCM_TAG_SIZE;
	static final int CHUNK_OVERHEAD = GCM_NONCE_SIZE + GCM_TAG_SIZE; // size of the empty EOF chunk
	static final long MAX_CHUNK_NUMBER = 4_294_967_294L;

}
