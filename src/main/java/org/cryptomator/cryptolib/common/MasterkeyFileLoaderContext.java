package org.cryptomator.cryptolib.common;

import java.nio.file.Path;

public interface MasterkeyFileLoaderContext {

	/**
	 * Provides the path of a masterkey file, if it could not be resolved automatically.
	 *
	 * @param incorrectPath The path as denoted by the key ID
	 * @return The correct path to a masterkey file or <code>null</code> to abort key loading.
	 */
	Path getMasterkeyFilePath(String incorrectPath);

	/**
	 * Provides the password for a given masterkey file.
	 *
	 * @param masterkeyFile For what masterkey file
	 * @return The passphrase or <code>null</code> to abort key loading.
	 */
	CharSequence getPassphrase(Path masterkeyFile);

}
