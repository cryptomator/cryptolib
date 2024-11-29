/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v3;

import java.nio.charset.StandardCharsets;

final class Constants {

	private Constants() {
	}

	static final String CONTENT_ENC_ALG = "AES";

	static final byte[] UVF_MAGIC_BYTES = "UVF0".getBytes(StandardCharsets.US_ASCII);

	static final int GCM_NONCE_SIZE = 12; // 96 bit IVs strongly recommended for GCM
	static final int PAYLOAD_SIZE = 32 * 1024;
	static final int GCM_TAG_SIZE = 16;
	static final int CHUNK_SIZE = GCM_NONCE_SIZE + PAYLOAD_SIZE + GCM_TAG_SIZE;

}
