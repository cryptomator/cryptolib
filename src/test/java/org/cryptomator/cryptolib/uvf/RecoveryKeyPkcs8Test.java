package org.cryptomator.cryptolib.uvf;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import org.cryptomator.cryptolib.internal.RecoveryKeys;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

/**
 * Vectors from Cryptomator Hub's {@code universalVaultFormat.spec.ts}: the recovery key of the Hub test user "alice".
 */
public class RecoveryKeyPkcs8Test {

	static final String HUB_WORDS = "cult hold all away buck do law relaxed other stimulus all bank fit indulge dad any ear grey cult golf all baby dig war linear tour sleep humanity threat question " //
			+ "neglect stance radar bank coup misery painter tragedy buddy compare winter national approval budget deep screen outdoor audience tear stream cure type ugly chamber " //
			+ "supporter franchise accept sexy ad imply being drug doctor regime where thick dam training grass chamber domestic dictator educate sigh music spoken connected measure " //
			+ "voice lemon pig comprise disturb appear greatly satisfied heat news curiosity top impress nor method reflect lesson recommend dual revenge thorough bus count broadband " //
			+ "living riot prejudice target blonde excess company thereby tribe respond horror mere way proud shopping wise liver mortgage plastic gentleman eighteen terms worry melt";
	static final byte[] HUB_PKCS8 = Base64.getDecoder().decode("MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDDCi4K1Ts3DgTz/ufkLX7EGMHjGpJv+WJmFgyzLwwaDFSfLpDw0Kgf3FKK+LAsV8r+hZANiAARLOtFebIjxVYUmDV09Q1sVxz2Nm+NkR8fu6UojVSRcCW13tEZatx8XGrIY9zC7oBCEdRqDc68PMSvS5RA0Pg9cdBNc/kgMZ1iEmEv5YsqOcaNADDSs0bLlXb35pX7Kx5Y=");
	static final String HUB_X = "SzrRXmyI8VWFJg1dPUNbFcc9jZvjZEfH7ulKI1UkXAltd7RGWrcfFxqyGPcwu6AQ";
	static final String HUB_Y = "hHUag3OvDzEr0uUQND4PXHQTXP5IDGdYhJhL-WLKjnGjQAw0rNGy5V29-aV-yseW";
	static final String HUB_THUMBPRINT = "T-LR82IaI1_TGHwcyn1u8vAYakGPz4upg1lPnE0xBZQ";

	static ECKey hubKeyPair() throws Exception {
		ECPrivateKey privateKey = RecoveryKeyPkcs8.decode(HUB_PKCS8);
		ECKey publicKey = new ECKey.Builder(Curve.P_384, new Base64URL(HUB_X), new Base64URL(HUB_Y)).build();
		return new ECKey.Builder(publicKey).privateKey(privateKey).build();
	}

	@Test
	@DisplayName("Hub words decode to Hub's PKCS#8")
	public void testDecodeHubWords() throws Exception {
		byte[] pkcs8 = RecoveryKeys.decode(HUB_WORDS, true);
		Assertions.assertArrayEquals(HUB_PKCS8, pkcs8);
		Assertions.assertEquals(RecoveryKeyPkcs8.LEN, pkcs8.length);
		ECPrivateKey key = RecoveryKeyPkcs8.decode(pkcs8);
		Assertions.assertEquals(Curve.P_384, Curve.forECParameterSpec(key.getParams()));
		Assertions.assertEquals(HUB_THUMBPRINT, hubKeyPair().computeThumbprint().toString(), "private key belongs to Hub's public key");
	}

	@Test
	@DisplayName("re-encoding Hub's key is byte-identical")
	public void testEncodeHubKey() throws Exception {
		byte[] pkcs8 = RecoveryKeyPkcs8.encode(hubKeyPair());
		Assertions.assertArrayEquals(HUB_PKCS8, pkcs8);
		Assertions.assertEquals(HUB_WORDS, RecoveryKeys.encode(pkcs8, true));
	}

	@Test
	@DisplayName("JDK's PKCS#8 layout (without public key) decodes too")
	public void testDecodeJdkLayout() throws Exception {
		KeyPair keyPair = generate("secp384r1");
		byte[] jdkPkcs8 = keyPair.getPrivate().getEncoded();
		Assertions.assertNotEquals(RecoveryKeyPkcs8.LEN, jdkPkcs8.length);
		ECPrivateKey decoded = RecoveryKeyPkcs8.decode(jdkPkcs8);
		Assertions.assertEquals(((ECPrivateKey) keyPair.getPrivate()).getS(), decoded.getS());
		// and a fresh key round-trips through our layout:
		ECKey ecKey = new ECKey.Builder(Curve.P_384, (ECPublicKey) keyPair.getPublic()).privateKey(decoded).build();
		byte[] ours = RecoveryKeyPkcs8.encode(ecKey);
		Assertions.assertEquals(RecoveryKeyPkcs8.LEN, ours.length);
		Assertions.assertEquals(decoded.getS(), RecoveryKeyPkcs8.decode(ours).getS());
		Assertions.assertEquals(126, RecoveryKeys.encode(ours, true).split(" ").length);
	}

	@Test
	@DisplayName("other curves and garbage are rejected")
	public void testInvalid() throws Exception {
		KeyPair p256 = generate("secp256r1");
		Assertions.assertThrows(IllegalArgumentException.class, () -> RecoveryKeyPkcs8.decode(p256.getPrivate().getEncoded()));
		Assertions.assertThrows(IllegalArgumentException.class, () -> RecoveryKeyPkcs8.decode(new byte[185]));
		Assertions.assertThrows(IllegalArgumentException.class, () -> RecoveryKeyPkcs8.decode(new byte[0]));
		ECKey p256Key = new ECKey.Builder(Curve.P_256, (ECPublicKey) p256.getPublic()).privateKey((ECPrivateKey) p256.getPrivate()).build();
		Assertions.assertThrows(IllegalArgumentException.class, () -> RecoveryKeyPkcs8.encode(p256Key));
		ECKey publicOnly = new ECKey.Builder(Curve.P_384, new Base64URL(HUB_X), new Base64URL(HUB_Y)).build();
		Assertions.assertThrows(IllegalArgumentException.class, () -> RecoveryKeyPkcs8.encode(publicOnly));
	}

	private static KeyPair generate(String curve) throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(new ECGenParameterSpec(curve), new SecureRandom());
		return generator.generateKeyPair();
	}

}
