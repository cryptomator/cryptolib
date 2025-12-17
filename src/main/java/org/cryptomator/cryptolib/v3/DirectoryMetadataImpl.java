package org.cryptomator.cryptolib.v3;

import org.cryptomator.cryptolib.api.DirectoryMetadata;

class DirectoryMetadataImpl implements DirectoryMetadata {

	private final int seedId;
	private final byte[] dirId;

	public DirectoryMetadataImpl(int seedId, byte[] dirId) {
		this.seedId = seedId;
		this.dirId = dirId;
	}

	static DirectoryMetadataImpl cast(DirectoryMetadata metadata) {
		if (metadata instanceof DirectoryMetadataImpl) {
			return (DirectoryMetadataImpl) metadata;
		} else {
			throw new IllegalArgumentException("Unsupported metadata type " + metadata.getClass());
		}
	}

	public byte[] dirId() {
		return dirId;
	}

	public int seedId() {
		return seedId;
	}

}
