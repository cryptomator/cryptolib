package org.cryptomator.cryptolib.api;

import java.io.IOException;

/**
 * Callback through which cryptolib writes small metadata files (e.g. {@code name.c9s}, {@code dir.c9r}, {@code dir.uvf}, {@code symlink.c9r}) into a vault.
 * <p>
 * Implementations must create missing parent directories. A typical implementation is:
 * <pre>{@code
 * (relPath, bytes) -> {
 *     Path file = vaultDir.resolve(relPath);
 *     Files.createDirectories(file.getParent());
 *     Files.write(file, bytes);
 * }
 * }</pre>
 */
@FunctionalInterface
public interface VaultWriter {

	/**
	 * Writes (creates or replaces) a file inside the vault.
	 *
	 * @param pathRelativeToVaultRoot Path of the file, relative to the vault's root directory, using {@code /} as separator
	 * @param contents The complete contents of the file
	 * @throws IOException If the file can not be written
	 */
	void write(String pathRelativeToVaultRoot, byte[] contents) throws IOException;

}
