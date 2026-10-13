package org.cryptomator.cryptolib.internal;

import org.cryptomator.cryptolib.api.LockedVault;
import org.cryptomator.cryptolib.api.VaultConfigLoadException;
import org.cryptomator.cryptolib.cvf8.Cvf8LockedVaultImpl;

import java.nio.charset.StandardCharsets;

/**
 * Format detection behind {@link LockedVault#parse(byte[])}. Not part of the public API.
 */
public final class LockedVaults {

	private LockedVaults() {
	}

	/**
	 * Parses a vault configuration file, detecting its format from the contents.
	 *
	 * @param fileContents Contents of {@code vault.cryptomator} or {@code vault.uvf}
	 * @return The locked vault
	 * @throws VaultConfigLoadException If the contents match neither format
	 */
	public static LockedVault parse(byte[] fileContents) throws VaultConfigLoadException {
		String text = new String(fileContents, StandardCharsets.UTF_8).trim();
		if (text.startsWith("{")) {
			return parseUvf(text);
		} else if (!text.isEmpty()) {
			return Cvf8LockedVaultImpl.parse(fileContents, text);
		} else {
			throw new VaultConfigLoadException("Empty vault config");
		}
	}

	private static LockedVault parseUvf(String json) throws VaultConfigLoadException {
		throw new VaultConfigLoadException("UVF not supported yet"); // TODO replaced by UvfLockedVaultImpl.parse in the uvf package
	}

}
