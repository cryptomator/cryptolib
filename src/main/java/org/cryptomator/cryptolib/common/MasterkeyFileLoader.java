package org.cryptomator.cryptolib.common;

import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.api.MasterkeyLoader;
import org.cryptomator.cryptolib.api.MasterkeyLoadingFailedException;

import java.net.URI;
import java.nio.file.Path;
import java.util.function.Function;

public class MasterkeyFileLoader<C extends VaultRootAwareContext> implements MasterkeyLoader<C> {

	private static final String SUPPORTED_SCHEME = "masterkeyfile";
	private final MasterkeyFileAccess masterkeyFileAccess;
	private final Function<C, CharSequence> passphraseProvider;

	MasterkeyFileLoader(MasterkeyFileAccess masterkeyFileAccess, Function<C, CharSequence> passphraseProvider) {
		this.masterkeyFileAccess = masterkeyFileAccess;
		this.passphraseProvider = passphraseProvider;
	}

	@Override
	public boolean supportsScheme(String scheme) {
		return SUPPORTED_SCHEME.equalsIgnoreCase(scheme);
	}

	@Override
	public Masterkey loadKey(URI keyId, C context) throws MasterkeyLoadingFailedException {
		assert SUPPORTED_SCHEME.equalsIgnoreCase(keyId.getScheme());
		Path filePath = context.getVaultRoot().resolve(keyId.getSchemeSpecificPart());
		CharSequence passphrase = passphraseProvider.apply(context);
		return masterkeyFileAccess.load(filePath, passphrase);
	}

}
