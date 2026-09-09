package org.cryptomator.cryptolib.common;

import java.io.IOException;

/**
 * Additional, caller-defined validation of a parsed {@link MasterkeyFile} before any key derivation happens.
 * <p>
 * Used by {@link MasterkeyFileAccess#load(java.nio.file.Path, CharSequence, MasterkeyFileValidator)} to reject files that are structurally valid
 * but unsuitable for the calling environment, e.g. because their scrypt parameters require more memory than the caller is willing to spend.
 */
@FunctionalInterface
public interface MasterkeyFileValidator {

	/**
	 * Validates the given, structurally valid masterkey file.
	 *
	 * @param masterkeyFile The parsed masterkey file
	 * @throws IOException If the file is rejected. The exception is propagated to the caller of {@link MasterkeyFileAccess#load(java.io.InputStream, CharSequence, MasterkeyFileValidator)}
	 */
	void validate(MasterkeyFile masterkeyFile) throws IOException;

}
