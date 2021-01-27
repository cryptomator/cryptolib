package org.cryptomator.cryptolib.common;

import org.cryptomator.cryptolib.api.MasterkeyLoadingFailedException;

import java.nio.file.Path;

public interface MasterkeyFileLoaderContext {

	/**
	 * Provides the path of a masterkey file, if it could not be resolved automatically.
	 *
	 * @param incorrectPath The path as denoted by the key ID
	 * @return The correct path to a masterkey file, must not be <code>null</code>
	 * @throws MasterkeyLoadingFailedException If the context is unable to provide a correct paath
	 */
	Path getCorrectMasterkeyFilePath(String incorrectPath) throws MasterkeyLoadingFailedException;

	/**
	 * Provides the password for a given masterkey file.
	 *
	 * @param masterkeyFile For what masterkey file
	 * @return The passphrase, must not be <code>null</code>
	 * @throws MasterkeyLoadingFailedException If the context is unable to provide a passphrase
	 */
	CharSequence getPassphrase(Path masterkeyFile) throws MasterkeyLoadingFailedException;

}
