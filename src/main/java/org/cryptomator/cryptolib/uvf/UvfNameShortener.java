package org.cryptomator.cryptolib.uvf;

import org.bouncycastle.util.encoders.Base32;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.NameShortener;
import org.cryptomator.cryptolib.api.ShortenedVaultNode;
import org.cryptomator.cryptolib.common.MessageDigestSupplier;
import org.cryptomator.cryptolib.internal.ShortenedVaultNodeImpl;
import org.cryptomator.cryptolib.internal.StrictUtf8;
import org.jspecify.annotations.Nullable;

import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.regex.Pattern;

/**
 * Name shortening of UVF: a name longer than the threshold is stored as {@code <hash>.shortened.uvf}, keeping its node type, next to the sidecar file {@code <hash>.original.uvf} holding
 * the full name. The hash is the Base32 encoding of the leftmost 160 bits of the name's SHA-256.
 *
 * @see <a href="https://github.com/encryption-alliance/unified-vault-format/tree/develop/file-name-shortening">UVF File Name Shortening</a>
 */
public final class UvfNameShortener implements NameShortener {

	// the scheme is still a draft (spec PR 37), keep its parameters in one place:
	private static final String SHORTENED_SUFFIX = ".shortened.uvf";
	private static final String SIDECAR_SUFFIX = ".original.uvf";
	private static final int TRUNCATED_HASH_BYTES = 20;
	private static final int HASH_LENGTH = 32; // 160 bits in base32
	private static final Pattern SHORTENED_NAME = Pattern.compile("[A-Z2-7]{32}\\.shortened\\.uvf");
	private static final Pattern SIDECAR_NAME = Pattern.compile("[A-Z2-7]{32}\\.original\\.uvf");

	private final int threshold;

	/**
	 * @param threshold Names with more UTF-8 bytes than this are shortened; {@link NameShortener#DISABLED} or at least {@link NameShortener#MIN_UVF_THRESHOLD}
	 * @throws IllegalArgumentException If the threshold is invalid
	 */
	public UvfNameShortener(int threshold) {
		this.threshold = requireValidThreshold(threshold);
	}

	/**
	 * @param threshold A name shortening threshold
	 * @return The threshold
	 * @throws IllegalArgumentException If the threshold is neither {@link NameShortener#DISABLED} nor at least {@link NameShortener#MIN_UVF_THRESHOLD}
	 */
	static int requireValidThreshold(int threshold) {
		if (threshold != DISABLED && threshold < MIN_UVF_THRESHOLD) {
			throw new IllegalArgumentException(String.format("Name shortening threshold must be %s or at least %s, but was %s", DISABLED, MIN_UVF_THRESHOLD, threshold));
		}
		return threshold;
	}

	@Override
	public int threshold() {
		return threshold;
	}

	@Override
	public @Nullable ShortenedVaultNode shorten(String name) {
		if (threshold == DISABLED) {
			return null;
		}
		byte[] utf8Name = name.getBytes(StandardCharsets.UTF_8);
		if (utf8Name.length <= threshold) {
			if (name.endsWith(SHORTENED_SUFFIX) || name.endsWith(SIDECAR_SUFFIX)) {
				throw new IllegalArgumentException("Reserved name: " + name);
			}
			return null;
		}
		String hash = hash(utf8Name);
		String shortenedName = hash + SHORTENED_SUFFIX;
		return new ShortenedVaultNodeImpl(name, //
				shortenedName, //
				shortenedName, //
				shortenedName + "/" + Constants.DIR_FILE_NAME, //
				shortenedName + "/" + Constants.SYMLINK_FILE_NAME, //
				hash + SIDECAR_SUFFIX);
	}

	@Override
	public boolean isShortened(String entryName) {
		return threshold != DISABLED && SHORTENED_NAME.matcher(entryName).matches();
	}

	@Override
	public boolean isSidecar(String entryName) {
		return threshold != DISABLED && SIDECAR_NAME.matcher(entryName).matches();
	}

	@Override
	public String sidecarFile(String shortenedName) {
		requireShortened(shortenedName);
		return shortenedName.substring(0, HASH_LENGTH) + SIDECAR_SUFFIX;
	}

	@Override
	public String unshorten(String shortenedName, byte[] sidecarContents) throws AuthenticationFailedException {
		requireShortened(shortenedName);
		if (sidecarContents.length <= threshold) {
			throw new AuthenticationFailedException("Sidecar of " + shortenedName + " holds a name that needs no shortening");
		}
		if (!hash(sidecarContents).equals(shortenedName.substring(0, HASH_LENGTH))) {
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

	private static String hash(byte[] utf8Name) {
		byte[] sha256 = MessageDigestSupplier.SHA256.instance().digest(utf8Name);
		return Base32.toBase32String(Arrays.copyOf(sha256, TRUNCATED_HASH_BYTES));
	}

}
