package org.cryptomator.cryptolib.common;

import java.nio.file.Path;

@FunctionalInterface
public interface VaultRootAwareContext {

	/**
	 * @return The vault's root path
	 */
	Path getVaultRoot();

}
