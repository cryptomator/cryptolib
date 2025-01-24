package org.cryptomator.cryptolib.v3;

import org.cryptomator.cryptolib.api.DirectoryMetadata;

class DirectoryMetadataImpl implements DirectoryMetadata {

	private final int seedId;
	private final byte[] dirId;

	public DirectoryMetadataImpl(int seedId, byte[] dirId) {
		this.seedId = seedId;
		this.dirId = dirId;
	}

	public byte[] dirId() {
		return dirId;
	}

	public int seedId() {
		return seedId;
	}

}
