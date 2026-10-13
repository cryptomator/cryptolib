package org.cryptomator.cryptolib.api;

import java.util.Map;

/**
 * One entry of the {@code recipients} array of a {@code vault.uvf} file, i.e. one party that can unlock the vault.
 */
public interface UvfRecipient {

	/**
	 * @return The recipient's key id ({@code kid}), or {@code null} if absent
	 */
	String kid();

	/**
	 * @return The JWE key management algorithm ({@code alg}) used for this recipient, e.g. {@code PBES2-HS512+A256KW} or {@code ECDH-ES+A256KW}
	 */
	String alg();

	/**
	 * @return The complete per-recipient unprotected header, including algorithm-specific parameters such as {@code p2s}, {@code p2c} or {@code epk} (unmodifiable)
	 */
	Map<String, Object> header();

}
