package org.cryptomator.cryptolib.cvf8;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.cryptomator.cryptolib.api.CipherCombo;
import org.cryptomator.cryptolib.api.CvfMasterkey;
import org.cryptomator.cryptolib.api.VaultConfigLoadException;
import org.cryptomator.cryptolib.api.VaultKeyInvalidException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.URI;
import java.util.Base64;

class Cvf8ConfigCodecTest {

	// vault.cryptomator in the layout written by cryptofs 2.x (auth0 java-jwt: header {"kid":..,"typ":"JWT","alg":"HS256"}, claims format/shorteningThreshold/jti/cipherCombo),
	// signed with masterkey 0x00..00: printf '%s' "$header.$payload" | openssl dgst -sha256 -mac HMAC -macopt hexkey:00..00 -binary | base64url
	private static final String CRYPTOFS_TOKEN = "eyJraWQiOiJtYXN0ZXJrZXlmaWxlOm1hc3RlcmtleS5jcnlwdG9tYXRvciIsInR5cCI6IkpXVCIsImFsZyI6IkhTMjU2In0.eyJmb3JtYXQiOjgsInNob3J0ZW5pbmdUaHJlc2hvbGQiOjIyMCwianRpIjoiNGMxZWI4MDktYTczYy00YmY2LTk2YWEtOWRhMmUzMjg4NGQyIiwiY2lwaGVyQ29tYm8iOiJTSVZfR0NNIn0.bYnrW2qbu0ZWZ3prx7WPxXCPgoAVpY3Ul8bCEXZ4jxI";

	private final CvfMasterkey masterkey = new CvfMasterkey(new byte[64]);

	@Test
	@DisplayName("parse token written by cryptofs 2.x")
	void testParseCryptofsToken() {
		Cvf8ConfigCodec.Claims claims = Cvf8ConfigCodec.parse(CRYPTOFS_TOKEN);
		Assertions.assertEquals(URI.create("masterkeyfile:masterkey.cryptomator"), claims.keyId);
		Assertions.assertEquals(8, claims.formatVersion);
		Assertions.assertEquals("SIV_GCM", claims.cipherCombo);
		Assertions.assertEquals(220, claims.shorteningThreshold);
		Assertions.assertEquals("4c1eb809-a73c-4bf6-96aa-9da2e32884d2", claims.vaultId);
	}

	@Test
	@DisplayName("verify token written by cryptofs 2.x")
	void testVerifyCryptofsToken() {
		Cvf8ConfigCodec.Claims claims = Cvf8ConfigCodec.parse(CRYPTOFS_TOKEN);
		Assertions.assertDoesNotThrow(() -> Cvf8ConfigCodec.verify(claims.jwt, masterkey));
	}

	@Test
	@DisplayName("verify with wrong key")
	void testVerifyWithWrongKey() {
		Cvf8ConfigCodec.Claims claims = Cvf8ConfigCodec.parse(CRYPTOFS_TOKEN);
		byte[] wrongKey = new byte[64];
		wrongKey[0] = 1;
		Assertions.assertThrows(VaultKeyInvalidException.class, () -> Cvf8ConfigCodec.verify(claims.jwt, new CvfMasterkey(wrongKey)));
	}

	@Test
	@DisplayName("verify tampered claims")
	void testVerifyTamperedToken() {
		String[] parts = CRYPTOFS_TOKEN.split("\\.");
		String tamperedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"format\":7,\"shorteningThreshold\":220,\"jti\":\"x\",\"cipherCombo\":\"SIV_GCM\"}".getBytes());
		Cvf8ConfigCodec.Claims claims = Cvf8ConfigCodec.parse(parts[0] + "." + tamperedPayload + "." + parts[2]);
		Assertions.assertEquals(7, claims.formatVersion);
		Assertions.assertThrows(VaultKeyInvalidException.class, () -> Cvf8ConfigCodec.verify(claims.jwt, masterkey));
	}

	@Test
	@DisplayName("sign and verify round trip")
	void testSignAndVerify() {
		String token = Cvf8ConfigCodec.sign("vault-id", URI.create("masterkeyfile:masterkey.cryptomator"), CipherCombo.SIV_GCM, 220, masterkey);
		Cvf8ConfigCodec.Claims claims = Cvf8ConfigCodec.parse(token);
		Assertions.assertEquals("vault-id", claims.vaultId);
		Assertions.assertEquals(URI.create("masterkeyfile:masterkey.cryptomator"), claims.keyId);
		Assertions.assertEquals(8, claims.formatVersion);
		Assertions.assertEquals("SIV_GCM", claims.cipherCombo);
		Assertions.assertEquals(220, claims.shorteningThreshold);
		Assertions.assertEquals(JOSEObjectType.JWT, claims.jwt.getHeader().getType());
		Assertions.assertEquals(JWSAlgorithm.HS256, claims.jwt.getHeader().getAlgorithm());
		Assertions.assertDoesNotThrow(() -> Cvf8ConfigCodec.verify(claims.jwt, masterkey));
	}

	@ParameterizedTest(name = "{0} is accepted")
	@ValueSource(strings = {"HS256", "HS384", "HS512"})
	void testHmacAlgorithms(String alg) throws Exception {
		SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.parse(alg)).keyID("masterkeyfile:masterkey.cryptomator").build(), claims(8));
		jwt.sign(new MACSigner(masterkey.getEncoded()));
		Cvf8ConfigCodec.Claims claims = Cvf8ConfigCodec.parse(jwt.serialize());
		Assertions.assertDoesNotThrow(() -> Cvf8ConfigCodec.verify(claims.jwt, masterkey));
	}

	@Test
	@DisplayName("alg none is rejected")
	void testNoneAlgorithmRejected() {
		String header = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"none\",\"kid\":\"masterkeyfile:masterkey.cryptomator\"}".getBytes());
		String payload = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"format\":8,\"shorteningThreshold\":220,\"jti\":\"x\",\"cipherCombo\":\"SIV_GCM\"}".getBytes());
		Assertions.assertThrows(VaultConfigLoadException.class, () -> Cvf8ConfigCodec.parse(header + "." + payload + "."));
	}

	@Test
	@DisplayName("missing kid is rejected")
	void testMissingKidRejected() throws Exception {
		SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).build(), claims(8));
		jwt.sign(new MACSigner(masterkey.getEncoded()));
		Assertions.assertThrows(VaultConfigLoadException.class, () -> Cvf8ConfigCodec.parse(jwt.serialize()));
	}

	@Test
	@DisplayName("missing claim is rejected")
	void testMissingClaimRejected() throws Exception {
		JWTClaimsSet claims = new JWTClaimsSet.Builder().claim("format", 8).claim("cipherCombo", "SIV_GCM").build();
		SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).keyID("masterkeyfile:masterkey.cryptomator").build(), claims);
		jwt.sign(new MACSigner(masterkey.getEncoded()));
		Assertions.assertThrows(VaultConfigLoadException.class, () -> Cvf8ConfigCodec.parse(jwt.serialize()));
	}

	@Test
	@DisplayName("garbage is rejected")
	void testGarbageRejected() {
		Assertions.assertThrows(VaultConfigLoadException.class, () -> Cvf8ConfigCodec.parse("not a token"));
	}

	private static JWTClaimsSet claims(int format) {
		return new JWTClaimsSet.Builder().jwtID("x").claim("format", format).claim("cipherCombo", "SIV_GCM").claim("shorteningThreshold", 220).build();
	}

}
