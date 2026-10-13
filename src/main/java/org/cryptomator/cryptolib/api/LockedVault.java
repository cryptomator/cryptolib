package org.cryptomator.cryptolib.api;

import org.cryptomator.cryptolib.internal.LockedVaults;

/**
 * A parsed but not yet authenticated vault configuration file ({@code vault.cryptomator} or {@code vault.uvf}).
 * <p>
 * Nothing read from a locked vault may be trusted. Every instance is either a {@link Cvf8LockedVault} or a {@link UvfLockedVault}; the respective {@code unlock} methods authenticate the
 * configuration and yield an {@link UnlockedVault}.
 *
 * @implNote On Java 25+ this interface is {@code sealed}. Keep this file in sync with {@code src/main/java25/.../LockedVault.java}.
 */
public interface LockedVault {

	/**
	 * Parses a vault configuration file, detecting its format from the contents.
	 *
	 * @param fileContents The contents of {@code vault.cryptomator} (a compact JWT) or {@code vault.uvf} (a JWE in JSON serialization)
	 * @return A {@link Cvf8LockedVault} or a {@link UvfLockedVault}
	 * @throws VaultConfigLoadException If the contents are neither
	 */
	static LockedVault parse(byte[] fileContents) throws VaultConfigLoadException {
		return LockedVaults.parse(fileContents);
	}

	/**
	 * @return The file name under which this format stores its configuration in the vault root ({@code vault.cryptomator} or {@code vault.uvf})
	 */
	String configFileName();

	/**
	 * @return The original file contents this instance was parsed from
	 */
	byte[] encoded();

}
