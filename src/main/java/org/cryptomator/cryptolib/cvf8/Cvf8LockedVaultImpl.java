package org.cryptomator.cryptolib.cvf8;

import org.cryptomator.cryptolib.api.CipherCombo;
import org.cryptomator.cryptolib.api.Cvf8LockedVault;
import org.cryptomator.cryptolib.api.Cvf8UnlockedVault;
import org.cryptomator.cryptolib.api.CvfMasterkey;
import org.cryptomator.cryptolib.api.MasterkeyLoader;
import org.cryptomator.cryptolib.api.MasterkeyLoadingFailedException;
import org.cryptomator.cryptolib.api.UnsupportedVaultFormatException;
import org.cryptomator.cryptolib.api.VaultConfigLoadException;
import org.cryptomator.cryptolib.api.VaultKeyInvalidException;

import java.net.URI;
import java.security.SecureRandom;

/**
 * {@link Cvf8LockedVault} backed by a parsed {@code vault.cryptomator} token.
 */
public final class Cvf8LockedVaultImpl implements Cvf8LockedVault {

	private final byte[] encoded;
	private final Cvf8ConfigCodec.Claims claims;

	private Cvf8LockedVaultImpl(byte[] encoded, Cvf8ConfigCodec.Claims claims) {
		this.encoded = encoded;
		this.claims = claims;
	}

	/**
	 * @param encoded The file contents
	 * @param token The file contents as trimmed string
	 * @return The locked vault
	 * @throws VaultConfigLoadException If the token is malformed
	 */
	public static Cvf8LockedVaultImpl parse(byte[] encoded, String token) throws VaultConfigLoadException {
		return new Cvf8LockedVaultImpl(encoded.clone(), Cvf8ConfigCodec.parse(token));
	}

	@Override
	public String configFileName() {
		return Constants.CONFIG_FILE_NAME;
	}

	@Override
	public byte[] encoded() {
		return encoded.clone();
	}

	@Override
	public URI keyId() {
		return claims.keyId;
	}

	@Override
	public int allegedFormatVersion() {
		return claims.formatVersion;
	}

	@Override
	public int allegedShorteningThreshold() {
		return claims.shorteningThreshold;
	}

	@Override
	public Cvf8UnlockedVault unlock(CvfMasterkey masterkey, SecureRandom csprng) throws VaultKeyInvalidException, UnsupportedVaultFormatException, VaultConfigLoadException {
		Cvf8ConfigCodec.verify(claims.jwt, masterkey);
		// from here on the claims are authentic:
		if (claims.formatVersion != Constants.VAULT_VERSION) {
			throw new UnsupportedVaultFormatException(claims.formatVersion, Constants.VAULT_VERSION);
		}
		CipherCombo cipherCombo;
		try {
			cipherCombo = CipherCombo.valueOf(claims.cipherCombo);
		} catch (IllegalArgumentException e) {
			throw new VaultConfigLoadException("Unsupported cipher combo: " + claims.cipherCombo, e);
		}
		if (claims.shorteningThreshold <= 0) {
			throw new VaultConfigLoadException("Invalid shortening threshold: " + claims.shorteningThreshold);
		}
		return new Cvf8Vault(masterkey.copy(), claims.vaultId, claims.keyId, cipherCombo, claims.shorteningThreshold, csprng);
	}

	@Override
	public Cvf8UnlockedVault unlock(MasterkeyLoader keyLoader, SecureRandom csprng) throws MasterkeyLoadingFailedException, VaultKeyInvalidException, UnsupportedVaultFormatException, VaultConfigLoadException {
		try (CvfMasterkey masterkey = keyLoader.loadKey(claims.keyId)) {
			return unlock(masterkey, csprng);
		}
	}

}
