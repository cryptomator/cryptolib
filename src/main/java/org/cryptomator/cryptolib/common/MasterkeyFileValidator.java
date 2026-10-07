package org.cryptomator.cryptolib.common;

import java.io.IOException;

/**
 * Validation of a parsed {@link MasterkeyFile} before any key derivation happens.
 * <p>
 * Used by {@link MasterkeyFileAccess#load(java.nio.file.Path, CharSequence, MasterkeyFileValidator)} to reject files that are structurally valid
 * but unsuitable for the calling environment, e.g. because their scrypt parameters require more memory than the caller is willing to spend.
 */
@FunctionalInterface
public interface MasterkeyFileValidator {

	/**
	 * Upper bound of the scrypt cost parameter <code>N</code> accepted by {@link #DEFAULT}.
	 */
	public static final int DEFAULT_MAX_SCRYPT_COST_PARAM = 1 << 20;

	/**
	 * Upper bound of the scrypt block size <code>r</code> accepted by {@link #DEFAULT}.
	 */
	public static final int DEFAULT_MAX_SCRYPT_BLOCK_SIZE = 64;

	/**
	 * Upper bound of the working memory in bytes the scrypt key derivation may require for files accepted by {@link #DEFAULT}.
	 */
	public static final long DEFAULT_MAX_SCRYPT_WORKING_MEMORY = 1024L * 1024 * 1024 + 3072; // 1 GiB for V plus 3 KiB for B and XY, allowing N=2^20, r=8

	/**
	 * Rejects masterkey files whose scrypt parameters exceed {@link #DEFAULT_MAX_SCRYPT_COST_PARAM}, {@link #DEFAULT_MAX_SCRYPT_BLOCK_SIZE} or {@link #DEFAULT_MAX_SCRYPT_WORKING_MEMORY}.
	 */
	public static final MasterkeyFileValidator DEFAULT = file -> {
		if (file.scryptCostParam > DEFAULT_MAX_SCRYPT_COST_PARAM
				|| file.scryptBlockSize > DEFAULT_MAX_SCRYPT_BLOCK_SIZE
				|| Scrypt.workingMemoryBytes(file.scryptCostParam, file.scryptBlockSize) > DEFAULT_MAX_SCRYPT_WORKING_MEMORY) {
			throw new IOException("scrypt parameters out of accepted range");
		}
	};


	/**
	 * Validates the given, structurally valid masterkey file.
	 *
	 * @param masterkeyFile The parsed masterkey file
	 * @throws IOException If the file is rejected. The exception is propagated to the caller of {@link MasterkeyFileAccess#load(java.io.InputStream, CharSequence, MasterkeyFileValidator)}
	 */
	void validate(MasterkeyFile masterkeyFile) throws IOException;

}
