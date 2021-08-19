package org.cryptomator.cryptolib.common;

import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.api.MasterkeyLoadingFailedException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;

public class MasterkeyHubAccessTest {

	private static final byte[] DEVICE_PKCS12 = BaseEncoding.base64Url().decode("MIIFhAIBAzCCBT0GCSqGSIb3DQEHAaCCBS" //
			+ "4EggUqMIIFJjCB6wYJKoZIhvcNAQcBoIHdBIHaMIHXMIHUBgsqhkiG9w0BDAoBAqCBiDCBhTApBgoqhkiG9w0BDAEDMBsEFGAM85ETk7ydc" //
			+ "BZlJOEO4_4t7LcGAgMAw1AEWLu-1SdjZkqjOdwiQBOFYJkrtZimD0AHst3LxOmdVJZGJ2my4hgxQJH2sIcEnpNwQnrlBcI80xy4bozDxZ6W" //
			+ "Asu-BymbjAqg86xpB6XBIQZj9NQ24OA1NuwxOjAVBgkqhkiG9w0BCRQxCB4GAGsAZQB5MCEGCSqGSIb3DQEJFTEUBBJUaW1lIDE2MjkzNjg" //
			+ "wNjExMzIwggQ0BgkqhkiG9w0BBwagggQlMIIEIQIBADCCBBoGCSqGSIb3DQEHATApBgoqhkiG9w0BDAEGMBsEFOAPMGdG_k1brTiSEjOV1P" //
			+ "X4bu8MAgMAw1CAggPgHpg-v843nCYSn9TPMR11UHT2puRiD-xo8CeHxavkEUZDZOwfk9E0Clhq7ibejxW7GgY3gmPxU9OvZNmXdGY6cI_7h" //
			+ "icyX6Ftvl2iZSouSDEpzzpFFut3zSjaY3T8VU0YbT2f1Kw_4EQRmr0QQxBLfp6mbcLyy4sPPB-n3Yej9LRU5_aa6MFYrWdw4chO3T1246v1" //
			+ "GqhvHvnpwXk989Rt0RFau57oV4Y2BWuYF5tL5njy0svOfWi9lL3k8NhezcBmzSm42JP69OLZE34tQNDhGWIkLn1XyALEHEJz6IcbRs-yAoB" //
			+ "S362cQFgrSKRjXnrLoPVYZMQOhlexBL4A2kuvNCF-DNEgoWUdHI1EkCUODV8a3gAFwucCsMpDBnwlU7AVMF75X2gWENG-MUd2bSWj6qK53y" //
			+ "iyqEjYguBp8Xxibi_jniX6Y9L-1xa5Q3ccthcjFXCne3l3-KXW3Nr98j6u6jz6HtJbblvUb_J4Y1R3M35s1380Qv80zvkUpkUHoCSbDFhY8" //
			+ "cikj5W3oE6wlfUhRjfmKzKZOrMuIoMqBkUA6rpEpq666_zOoD-Cxay62HjWWiueTiELKEtbe-Dq8_dqX5LZ27P2wWEiOXInv8pKKiHAxSQn" //
			+ "qzn7FOH7KCh4u-cMemi-0itjP6KFbW_dpg0cca6RHyIPSCUejlyvfr0Spewf9D2q3j7iTK1QZL_nQck2TcdeVjE7_PpwX3hPDGtt9PFYFBL" //
			+ "4od93JmcutaRXm0iXUNkBwwXf53Eiw8vTRwPkdJ-w6z6Bl4jjWMS5yDPPx--UscCooEgGJOpJivTFGwaa2f-vt4N4P0jfA2vZVIrz1II-T8" //
			+ "O8DaVw7TtgsgfDm8DBXyoCESXY37ss58NVOWsqSgF8-TD4Rzpy2DCb9NC5tn_wLCt2vErg8veWVrNo99fXqOdDI0ymoEyqUB2sKqcDfIo0s" //
			+ "mB_DFbcxmqFNG9tsS9O7Lg3L045eZlnM6u0G2hmPcOw5aHhZ3ZhL2s7S46-EJSvvYqLTlB2KTH-ww6JnftiEmKva6ABUuhmCD101XSFg0rh" //
			+ "eYFFxtoIbFVXC7V6L3tv3IbSmI-jWDapJYgYjDapmBLaGRJyEU_oxILOPJEKvQnPdRORcNsYuKc3QZXLMKkTC1XtOzal6I5w_HcXPu8y19y" //
			+ "ZpPP0NAl-QwFVI2s4Ch7UJYP-cbRee4sJzKzmLG7vM8_NrJLH_m-ecLqh2ahHpc4W-7bqbNJnbJ9E8Cvm4urGxTeyTlz3boGoBJXbtQx67T" //
			+ "1bvj1Z-bFvOcSrX7UfDb-NMIaK09wxOyFO6wTD6B_VOEyChFuv0wWMLaYwPjAhMAkGBSsOAwIaBQAEFP9S30F1lPqFdDzVCTDtH1gXqITXB" //
			+ "BSXiYwuLjMqaiwdT_Xbi0ue97zSVQIDAYag");

	private P384KeyPair deviceKey;

	@BeforeEach
	public void setup() throws IOException {
		this.deviceKey = P384KeyPair.load(new ByteArrayInputStream(DEVICE_PKCS12), "secret".toCharArray());
	}

	@Test
	@DisplayName("decryptMasterkey(...)")
	public void testDecrypt() {
		String ephPk = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEkcv3x-hkCnb8Kr8TNfaLpD4q64ZqPn4p1yuM8r2r16h6f6mG01kFBp2EoY575bCcmT54PxiDFkf3KKqHXFjZwBhdm6zMp22l37ZlmKyHG96vkB7Rh6qFyzEhSQ_nvl2G";
		String ciphertext = "KQ48XS6ziW3tS7SMLR5sc2o_Y80OR4SS_htHpk8SHn4KrqI07EtDFFbNJ9AcNOazSu3TXrml--t_bEXprfnPqa3MlBvmPUVBcwUFJPDTR9Y";

		Masterkey masterkey = MasterkeyHubAccess.decryptMasterkey(deviceKey, ciphertext, ephPk);

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
			MasterkeyHubAccess.decryptMasterkey(deviceKey, ciphertext, ephPk);
		});
	}

	@Test
	@DisplayName("decryptMasterkey(...) with tampered ciphertext")
	public void testDecryptWithInvalidCiphertext() {
		String ephPk = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEkcv3x-hkCnb8Kr8TNfaLpD4q64ZqPn4p1yuM8r2r16h6f6mG01kFBp2EoY575bCcmT54PxiDFkf3KKqHXFjZwBhdm6zMp22l37ZlmKyHG96vkB7Rh6qFyzEhSQ_nvl2G";
		String ciphertext = "kQ48XS6ziW3tS7SMLR5sc2o_Y80OR4SS_htHpk8SHn4KrqI07EtDFFbNJ9AcNOazSu3TXrml--t_bEXprfnPqa3MlBvmPUVBcwUFJPDTR9Y";

		Assertions.assertThrows(MasterkeyLoadingFailedException.class, () -> {
			MasterkeyHubAccess.decryptMasterkey(deviceKey, ciphertext, ephPk);
		});
	}

	@Test
	@DisplayName("decryptMasterkey(...) with invalid device key")
	public void testDecryptWithInvalidDeviceKey() {
		String ephPk = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEkcv3x-hkCnb8Kr8TNfaLpD4q64ZqPn4p1yuM8r2r16h6f6mG01kFBp2EoY575bCcmT54PxiDFkf3KKqHXFjZwBhdm6zMp22l37ZlmKyHG96vkB7Rh6qFyzEhSQ_nvl2G";
		String ciphertext = "KQ48XS6ziW3tS7SMLR5sc2o_Y80OR4SS_htHpk8SHn4KrqI07EtDFFbNJ9AcNOazSu3TXrml--t_bEXprfnPqa3MlBvmPUVBcwUFJPDTR9Y";
		P384KeyPair wrongKey = P384KeyPair.generate();

		Assertions.assertThrows(MasterkeyLoadingFailedException.class, () -> {
			MasterkeyHubAccess.decryptMasterkey(wrongKey, ciphertext, ephPk);
		});
	}

}