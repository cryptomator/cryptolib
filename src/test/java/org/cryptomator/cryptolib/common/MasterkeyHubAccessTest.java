package org.cryptomator.cryptolib.common;

import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.api.MasterkeyLoadingFailedException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

public class MasterkeyHubAccessTest {

	private ECPrivateKey devicePrivateKey;

	@BeforeEach
	public void setup() throws NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] keyBytes = BaseEncoding.base64Url().decode("ME4CAQAwEAYHKoZIzj0CAQYFK4EEACIENzA1AgEBBDDzj9mBnoqoYTO0wQDvM2iyI2wrNe468US1mHMjdJcKWGGvky4pMexIvmvmDsZLdsY");
		this.devicePrivateKey = (ECPrivateKey) KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
	}

	@Test
	@DisplayName("decryptMasterkey(...)")
	public void testDecrypt() {
		String ephPk = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEkcv3x-hkCnb8Kr8TNfaLpD4q64ZqPn4p1yuM8r2r16h6f6mG01kFBp2EoY575bCcmT54PxiDFkf3KKqHXFjZwBhdm6zMp22l37ZlmKyHG96vkB7Rh6qFyzEhSQ_nvl2G";
		String ciphertext = "KQ48XS6ziW3tS7SMLR5sc2o_Y80OR4SS_htHpk8SHn4KrqI07EtDFFbNJ9AcNOazSu3TXrml--t_bEXprfnPqa3MlBvmPUVBcwUFJPDTR9Y";

		Masterkey masterkey = MasterkeyHubAccess.decryptMasterkey(devicePrivateKey, ciphertext, ephPk);

		byte[] expectedKey = new byte[64];
		Arrays.fill(expectedKey, 0, 32, (byte) 0x55);
		Arrays.fill(expectedKey, 32, 64, (byte) 0x77);
		Assertions.assertArrayEquals(expectedKey, masterkey.getEncoded());
	}

	@Test
	@DisplayName("decryptMasterkey(...) with tampered ephemeral public key")
	public void testDecryptWithInvalidEphemeralPublicKey() {
		String ephPk = "mHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEkcv3x-hkCnb8Kr8TNfaLpD4q64ZqPn4p1yuM8r2r16h6f6mG01kFBp2EoY575bCcmT54PxiDFkf3KKqHXFjZwBhdm6zMp22l37ZlmKyHG96vkB7Rh6qFyzEhSQ_nvl2G";
		String ciphertext = "KQ48XS6ziW3tS7SMLR5sc2o_Y80OR4SS_htHpk8SHn4KrqI07EtDFFbNJ9AcNOazSu3TXrml--t_bEXprfnPqa3MlBvmPUVBcwUFJPDTR9Y";

		Assertions.assertThrows(MasterkeyLoadingFailedException.class, () -> {
			MasterkeyHubAccess.decryptMasterkey(devicePrivateKey, ciphertext, ephPk);
		});
	}

	@Test
	@DisplayName("decryptMasterkey(...) with tampered ciphertext")
	public void testDecryptWithInvalidCiphertext() {
		String ephPk = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEkcv3x-hkCnb8Kr8TNfaLpD4q64ZqPn4p1yuM8r2r16h6f6mG01kFBp2EoY575bCcmT54PxiDFkf3KKqHXFjZwBhdm6zMp22l37ZlmKyHG96vkB7Rh6qFyzEhSQ_nvl2G";
		String ciphertext = "kQ48XS6ziW3tS7SMLR5sc2o_Y80OR4SS_htHpk8SHn4KrqI07EtDFFbNJ9AcNOazSu3TXrml--t_bEXprfnPqa3MlBvmPUVBcwUFJPDTR9Y";

		Assertions.assertThrows(MasterkeyLoadingFailedException.class, () -> {
			MasterkeyHubAccess.decryptMasterkey(devicePrivateKey, ciphertext, ephPk);
		});
	}

	@Test
	@DisplayName("decryptMasterkey(...) with invalid device key")
	public void testDecryptWithInvalidDeviceKey() {
		String ephPk = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEkcv3x-hkCnb8Kr8TNfaLpD4q64ZqPn4p1yuM8r2r16h6f6mG01kFBp2EoY575bCcmT54PxiDFkf3KKqHXFjZwBhdm6zMp22l37ZlmKyHG96vkB7Rh6qFyzEhSQ_nvl2G";
		String ciphertext = "KQ48XS6ziW3tS7SMLR5sc2o_Y80OR4SS_htHpk8SHn4KrqI07EtDFFbNJ9AcNOazSu3TXrml--t_bEXprfnPqa3MlBvmPUVBcwUFJPDTR9Y";
		ECPrivateKey wrongKey = P384KeyPair.generate().getPrivate();

		Assertions.assertThrows(MasterkeyLoadingFailedException.class, () -> {
			MasterkeyHubAccess.decryptMasterkey(wrongKey, ciphertext, ephPk);
		});
	}

}