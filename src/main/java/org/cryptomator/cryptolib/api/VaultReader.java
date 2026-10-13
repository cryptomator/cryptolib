package org.cryptomator.cryptolib.api;

import java.io.IOException;

/**
 * Callback through which cryptolib reads small metadata files (e.g. {@code name.c9s}, {@code dir.c9r}, {@code dir.uvf}, {@code symlink.c9r}) from a vault.
 * <p>
 * A typical implementation is {@code relPath -> Files.readAllBytes(vaultDir.resolve(relPath))}.
 */
@FunctionalInterface
public interface VaultReader {

	/**
	 * Reads the complete contents of a file inside the vault.
	 *
	 * @param pathRelativeToVaultRoot Path of the file, relative to the vault's root directory, using {@code /} as separator
	 * @return The file's contents
	 * @throws IOException If the file can not be read
	 */
	byte[] read(String pathRelativeToVaultRoot) throws IOException;

}
