package org.cryptomator.cryptolib.cvf8;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.cryptomator.cryptolib.api.CipherCombo;
import org.cryptomator.cryptolib.api.CvfMasterkey;
import org.cryptomator.cryptolib.api.VaultConfigLoadException;
import org.cryptomator.cryptolib.api.VaultKeyInvalidException;

import java.net.URI;
import java.text.ParseException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Reads, verifies and writes the {@code vault.cryptomator} JWT.
 */
final class Cvf8ConfigCodec {

	static final String CLAIM_FORMAT = "format";
	static final String CLAIM_CIPHER_COMBO = "cipherCombo";
	static final String CLAIM_SHORTENING_THRESHOLD = "shorteningThreshold";
	private static final Set<JWSAlgorithm> ALLOWED_ALGORITHMS = new HashSet<>(Arrays.asList(JWSAlgorithm.HS256, JWSAlgorithm.HS384, JWSAlgorithm.HS512));

	private Cvf8ConfigCodec() {
	}

	/**
	 * Parsed, unverified claims of a token.
	 */
	static final class Claims {

		final SignedJWT jwt;
		final URI keyId;
		final String vaultId;
		final int formatVersion;
		final String cipherCombo;
		final int shorteningThreshold;

		private Claims(SignedJWT jwt, URI keyId, String vaultId, int formatVersion, String cipherCombo, int shorteningThreshold) {
			this.jwt = jwt;
			this.keyId = keyId;
			this.vaultId = vaultId;
			this.formatVersion = formatVersion;
			this.cipherCombo = cipherCombo;
			this.shorteningThreshold = shorteningThreshold;
		}

	}

	/**
	 * Parses a token without verifying its signature.
	 *
	 * @param token The compact JWT
	 * @return Its header and claims
	 * @throws VaultConfigLoadException If the token is malformed or lacks required fields
	 */
	static Claims parse(String token) throws VaultConfigLoadException {
		try {
			SignedJWT jwt = SignedJWT.parse(token);
			if (!ALLOWED_ALGORITHMS.contains(jwt.getHeader().getAlgorithm())) {
				throw new VaultConfigLoadException("Unsupported signature algorithm: " + jwt.getHeader().getAlgorithm());
			}
			String kid = jwt.getHeader().getKeyID();
			if (kid == null) {
				throw new VaultConfigLoadException("Vault config lacks key id (kid)");
			}
			JWTClaimsSet claims = jwt.getJWTClaimsSet();
			Integer format = claims.getIntegerClaim(CLAIM_FORMAT);
			String cipherCombo = claims.getStringClaim(CLAIM_CIPHER_COMBO);
			Integer shorteningThreshold = claims.getIntegerClaim(CLAIM_SHORTENING_THRESHOLD);
			if (format == null || cipherCombo == null || shorteningThreshold == null) {
				throw new VaultConfigLoadException("Vault config lacks required claims");
			}
			return new Claims(jwt, URI.create(kid), claims.getJWTID(), format, cipherCombo, shorteningThreshold);
		} catch (ParseException | IllegalArgumentException e) {
			throw new VaultConfigLoadException("Failed to parse vault config", e);
		}
	}

	/**
	 * Verifies a token's signature.
	 *
	 * @param jwt The token
	 * @param masterkey The key to verify with
	 * @throws VaultKeyInvalidException If the signature does not verify
	 */
	static void verify(SignedJWT jwt, CvfMasterkey masterkey) throws VaultKeyInvalidException {
		byte[] rawKey = masterkey.getEncoded().clone(); // getEncoded() returns the live array
		try {
			if (!jwt.verify(new MACVerifier(rawKey))) {
				throw new VaultKeyInvalidException("Vault config signature does not match the provided key");
			}
		} catch (JOSEException e) {
			throw new VaultKeyInvalidException("Failed to verify vault config", e);
		} finally {
			Arrays.fill(rawKey, (byte) 0x00);
		}
	}

	/**
	 * Creates a signed token.
	 *
	 * @param vaultId The {@code jti} claim
	 * @param keyId The {@code kid} header
	 * @param cipherCombo The {@code cipherCombo} claim
	 * @param shorteningThreshold The {@code shorteningThreshold} claim
	 * @param masterkey The key to sign with (HS256)
	 * @return The compact JWT
	 */
	static String sign(String vaultId, URI keyId, CipherCombo cipherCombo, int shorteningThreshold, CvfMasterkey masterkey) {
		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256).type(JOSEObjectType.JWT).keyID(keyId.toString()).build();
		JWTClaimsSet claims = new JWTClaimsSet.Builder() //
				.jwtID(vaultId) //
				.claim(CLAIM_FORMAT, Constants.VAULT_VERSION) //
				.claim(CLAIM_CIPHER_COMBO, cipherCombo.name()) //
				.claim(CLAIM_SHORTENING_THRESHOLD, shorteningThreshold) //
				.build();
		SignedJWT jwt = new SignedJWT(header, claims);
		byte[] rawKey = masterkey.getEncoded().clone(); // getEncoded() returns the live array
		try {
			jwt.sign(new MACSigner(rawKey));
			return jwt.serialize();
		} catch (JOSEException e) {
			throw new IllegalStateException("Failed to sign vault config", e);
		} finally {
			Arrays.fill(rawKey, (byte) 0x00);
		}
	}

}
