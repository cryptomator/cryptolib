package org.cryptomator.cryptolib.internal;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;

/**
 * Validation of decrypted node names, which are untrusted input: another recipient may have stored arbitrary values.
 */
public final class CleartextNames {

	private CleartextNames() {
	}

	/**
	 * Rejects names that must never reach a file system: empty names, {@code .}, {@code ..} and names containing {@code /} or NUL. File system specific rules remain the caller's job.
	 *
	 * @param name A decrypted name
	 * @return The name
	 * @throws AuthenticationFailedException If the name is not a valid file name
	 */
	public static String validate(String name) throws AuthenticationFailedException {
		if (name.isEmpty() || name.equals(".") || name.equals("..") || name.indexOf('/') >= 0 || name.indexOf('\0') >= 0) {
			throw new AuthenticationFailedException("Decrypted name is not a valid file name");
		}
		return name;
	}

}
