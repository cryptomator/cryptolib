package org.cryptomator.cryptolib.cvf8;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.NameShortener;
import org.cryptomator.cryptolib.api.ShortenedVaultNode;
import org.cryptomator.cryptolib.common.MessageDigestSupplier;
import org.cryptomator.cryptolib.internal.ShortenedVaultNodeImpl;
import org.cryptomator.cryptolib.internal.StrictUtf8;
import org.jspecify.annotations.Nullable;

import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * Name shortening of CVF8: a name longer than the threshold is stored as directory {@code base64url(SHA-1(name)).c9s}, which contains the full name in {@code name.c9s} and, for a
 * regular file, the contents in {@code contents.c9r}.
 */
public final class Cvf8NameShortener implements NameShortener {

	private static final Base64.Encoder BASE64URL = Base64.getUrlEncoder();
	private static final Pattern SHORTENED_NAME = Pattern.compile("[A-Za-z0-9_-]{27}=\\.c9s"); // 20 bytes in padded base64url

	private final int threshold;

	/**
	 * @param threshold Names with more characters than this are shortened
	 */
	public Cvf8NameShortener(int threshold) {
		this.threshold = threshold;
	}

	@Override
	public int threshold() {
		return threshold;
	}

	@Override
	public @Nullable ShortenedVaultNode shorten(String name) {
		if (name.length() <= threshold) {
			if (name.endsWith(Constants.SHORTENED_FILE_EXT)) {
				throw new IllegalArgumentException("Reserved name: " + name);
			}
			return null;
		}
		String shortenedName = shortenedName(name.getBytes(StandardCharsets.UTF_8));
		return new ShortenedVaultNodeImpl(name, //
				shortenedName, //
				shortenedName + "/" + Constants.CONTENTS_FILE_NAME, //
				shortenedName + "/" + Constants.DIR_FILE_NAME, //
				shortenedName + "/" + Constants.SYMLINK_FILE_NAME, //
				shortenedName + "/" + Constants.SIDECAR_FILE_NAME);
	}

	@Override
	public boolean isShortened(String entryName) {
		return SHORTENED_NAME.matcher(entryName).matches();
	}

	@Override
	public boolean isSidecar(String entryName) {
		return false; // name.c9s lives inside the shortened entry
	}

	@Override
	public String sidecarFile(String shortenedName) {
		requireShortened(shortenedName);
		return shortenedName + "/" + Constants.SIDECAR_FILE_NAME;
	}

	@Override
	public String unshorten(String shortenedName, byte[] sidecarContents) throws AuthenticationFailedException {
		requireShortened(shortenedName);
		if (!shortenedName(sidecarContents).equals(shortenedName)) {
			throw new AuthenticationFailedException("Sidecar contents do not belong to " + shortenedName);
		}
		try {
			return StrictUtf8.decode(sidecarContents);
		} catch (CharacterCodingException e) {
			throw new AuthenticationFailedException("Sidecar of " + shortenedName + " is not valid UTF-8", e);
		}
	}

	private void requireShortened(String shortenedName) {
		if (!isShortened(shortenedName)) {
			throw new IllegalArgumentException("Not a shortened name: " + shortenedName);
		}
	}

	private static String shortenedName(byte[] utf8Name) {
		byte[] hash = MessageDigestSupplier.SHA1.instance().digest(utf8Name);
		return BASE64URL.encodeToString(hash) + Constants.SHORTENED_FILE_EXT;
	}

}
