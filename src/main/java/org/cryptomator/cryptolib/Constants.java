/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib;

final class Constants {

	private Constants() {
	}

	static final Integer CURRENT_VAULT_VERSION = 3;

	static final String ENC_ALG = "AES";
	static final String MAC_ALG = "HmacSHA256";

	static final int KEY_LEN_BYTES = 32;
	static final int DEFAULT_SCRYPT_SALT_LENGTH = 8;
	static final int DEFAULT_SCRYPT_COST_PARAM = 1 << 14;
	static final int DEFAULT_SCRYPT_BLOCK_SIZE = 8;

	public static final int PAYLOAD_SIZE = 32 * 1024;
	public static final int NONCE_SIZE = 16;
	public static final int MAC_SIZE = 32;
	public static final int CHUNK_SIZE = NONCE_SIZE + PAYLOAD_SIZE + MAC_SIZE;
	public static final int PADDING_LOWER_BOUND = 4 * 1024; // 4k
	public static final int PADDING_UPPER_BOUND = 16 * 1024 * 1024; // 16M

}
