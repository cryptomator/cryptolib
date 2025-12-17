package org.cryptomator.cryptolib.v2;

import org.cryptomator.cryptolib.api.DirectoryMetadata;

class DirectoryMetadataImpl implements DirectoryMetadata {

	private final byte[] dirId;

	public DirectoryMetadataImpl(byte[] dirId) {
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

}
