package org.cryptomator.cryptolib.api;

import org.cryptomator.cryptolib.cvf8.Cvf8NameShortener;
import org.cryptomator.cryptolib.uvf.UvfNameShortener;
import org.jspecify.annotations.Nullable;

/**
 * Maps names that are too long for the underlying storage to short names and back.
 * <p>
 * Shortening is independent of name encryption: it involves no keys, performs no I/O and treats names as opaque strings. A long name is stored under a name derived from its hash, and a
 * sidecar file holds the full name. On the way back the sidecar's contents are verified against that hash. Reading and writing sidecars, caching and the order of file operations are up
 * to the caller. All paths are relative to the directory containing the entry and use {@code /} as separator.
 * <p>
 * Instances are immutable and thread-safe. {@link UnlockedVault#nameShortener()} returns the one matching a vault's configuration.
 */
public interface NameShortener {

	/**
	 * The smallest threshold that enables shortening for the Unified Vault Format: the length of a shortened name.
	 */
	int MIN_UVF_THRESHOLD = 46;

	/**
	 * The threshold denoting that names are not shortened.
	 */
	int DISABLED = -1;

	/**
	 * Creates the shortener of Cryptomator Vault Format 8: a long name is stored as directory {@code <hash>.c9s} containing {@code name.c9s}.
	 *
	 * @param threshold Names with more characters than this are shortened; Cryptomator uses 220
	 * @return The shortener
	 */
	static NameShortener cvf8(int threshold) {
		return new Cvf8NameShortener(threshold);
	}

	/**
	 * Creates the shortener of the Unified Vault Format: a long name is stored as {@code <hash>.shortened.uvf} next to {@code <hash>.original.uvf}.
	 *
	 * @param threshold Names with more UTF-8 bytes than this are shortened; {@link #DISABLED} or at least {@link #MIN_UVF_THRESHOLD}, 220 is recommended
	 * @return The shortener
	 * @throws IllegalArgumentException If the threshold is invalid
	 */
	static NameShortener uvf(int threshold) {
		return new UvfNameShortener(threshold);
	}

	/**
	 * @return The threshold above which names are shortened, or {@link #DISABLED}
	 */
	int threshold();

	/**
	 * Computes how a name is stored if it exceeds the threshold.
	 *
	 * @param name A name as produced by the layer above, usually {@link VaultNode#name()}
	 * @return The shortened node, or {@code null} if the name does not exceed the threshold and is stored as is
	 * @throws IllegalArgumentException If the name is not long but reserved, i.e. it would be mistaken for a shortened name or a sidecar
	 */
	@Nullable ShortenedVaultNode shorten(String name);

	/**
	 * @param entryName The name of an entry found in a directory
	 * @return {@code true} if the entry is stored under a shortened name, whose full name is held by {@link #sidecarFile(String)}
	 */
	boolean isShortened(String entryName);

	/**
	 * @param entryName The name of an entry found in a directory
	 * @return {@code true} if the entry is a sidecar file and must be hidden from the layer above; never the case for Cryptomator Vault Format 8, which stores sidecars inside the entry
	 */
	boolean isSidecar(String entryName);

	/**
	 * @param shortenedName The name of a shortened entry
	 * @return Path of the sidecar file holding the entry's full name
	 * @throws IllegalArgumentException If {@code shortenedName} is not a {@link #isShortened(String) shortened name}
	 */
	String sidecarFile(String shortenedName);

	/**
	 * Restores the full name of a shortened entry from its sidecar, verifying that the sidecar belongs to the entry.
	 *
	 * @param shortenedName The name of a shortened entry
	 * @param sidecarContents The contents of the file at {@link #sidecarFile(String)}
	 * @return The full name
	 * @throws IllegalArgumentException If {@code shortenedName} is not a {@link #isShortened(String) shortened name}
	 * @throws AuthenticationFailedException If the contents are not valid UTF-8 or do not hash to {@code shortenedName}, or (Unified Vault Format) do not exceed the threshold
	 */
	String unshorten(String shortenedName, byte[] sidecarContents) throws AuthenticationFailedException;

}
