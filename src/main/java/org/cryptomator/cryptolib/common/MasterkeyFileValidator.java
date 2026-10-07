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
	 * Rejects masterkey files whose scrypt parameters exceed the upper bounds accepted by this library, limiting the working memory of the key derivation to ~1 GiB.
	 */
	public static final MasterkeyFileValidator DEFAULT = file -> {
		if (file.scryptCostParam > DEFAULT_MAX_SCRYPT_COST_PARAM
				|| file.scryptBlockSize > DEFAULT_MAX_SCRYPT_BLOCK_SIZE
				|| Scrypt.exceedsWorkingMemoryLimit(file.scryptCostParam, file.scryptBlockSize)) {
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
