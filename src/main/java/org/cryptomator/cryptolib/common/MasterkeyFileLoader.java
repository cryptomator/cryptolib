package org.cryptomator.cryptolib.common;

import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.api.MasterkeyLoader;
import org.cryptomator.cryptolib.api.MasterkeyLoadingFailedException;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * A {@link MasterkeyLoader} for keys with the {@value #SCHEME} scheme.
 * <p>
 * Instances of this class are {@link MasterkeyFileLoaderContext context}-specific and should be obtained
 * via {@link MasterkeyFileAccess#keyLoader(Path, MasterkeyFileLoaderContext)}
 * <p>
 * This key loader {@link #loadKey(URI) loads} a vault's masterkey by interpreting the key ID as a path,
 * either absolute or relative to the root directory of the vault, pointing to a masterkey file containing
 * information that (paired with the correct passphrase) can be used to derive the masterkey.
 */
public class MasterkeyFileLoader implements MasterkeyLoader {

	public static final String SCHEME = "masterkeyfile";

	private final Path vaultRoot;
	private final MasterkeyFileAccess masterkeyFileAccess;
	private final MasterkeyFileLoaderContext context;

	MasterkeyFileLoader(Path vaultRoot, MasterkeyFileAccess masterkeyFileAccess, MasterkeyFileLoaderContext context) {
		this.vaultRoot = vaultRoot;
		this.masterkeyFileAccess = masterkeyFileAccess;
		this.context = context;
	}

	/**
	 * @param masterkeyFilePath Vault-relative or absolute path to a masterkey file.
	 * @return A new URI that can be used as key ID
	 */
	public static URI keyId(String masterkeyFilePath) {
		try {
			return new URI(SCHEME, masterkeyFilePath, null);
		} catch (URISyntaxException e) {
			throw new IllegalArgumentException("Can't create URI from " + SCHEME + ":" + masterkeyFilePath, e);
		}
	}

	@Override
	public boolean supportsScheme(String scheme) {
		return SCHEME.equalsIgnoreCase(scheme);
	}

	@Override
	public Masterkey loadKey(URI keyId) throws MasterkeyLoadingFailedException {
		assert SCHEME.equalsIgnoreCase(keyId.getScheme());
		Path filePath = vaultRoot.resolve(keyId.getSchemeSpecificPart());
		if (!Files.exists(filePath)) {
			filePath = context.getCorrectMasterkeyFilePath(keyId.getSchemeSpecificPart());
		}
		CharSequence passphrase = context.getPassphrase(filePath);
		return masterkeyFileAccess.load(filePath, passphrase);
	}

}
