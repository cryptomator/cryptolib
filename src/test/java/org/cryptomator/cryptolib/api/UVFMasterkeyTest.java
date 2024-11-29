package org.cryptomator.cryptolib.api;

import org.cryptomator.cryptolib.common.DestroyableSecretKey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

class UVFMasterkeyTest {

	@Test
	public void testFromDecryptedPayload() {
		String json = "{\n" +
				"    \"fileFormat\": \"AES-256-GCM-32k\",\n" +
				"    \"nameFormat\": \"AES-SIV-512-B64URL\",\n" +
				"    \"seeds\": {\n" +
				"        \"HDm38i\": \"ypeBEsobvcr6wjGzmiPcTaeG7/gUfE5yuYB3ha/uSLs=\",\n" +
				"        \"gBryKw\": \"PiPoFgA5WUoziU9lZOGxNIu9egCI1CxKy3PurtWcAJ0=\",\n" +
				"        \"QBsJFo\": \"Ln0sA6lQeuJl7PW1NWiFpTOTogKdJBOUmXJloaJa78Y=\"\n" +
				"    },\n" +
				"    \"initialSeed\": \"HDm38i\",\n" +
				"    \"latestSeed\": \"QBsJFo\",\n" +
				"    \"kdf\": \"HKDF-SHA512\",\n" +
				"    \"kdfSalt\": \"NIlr89R7FhochyP4yuXZmDqCnQ0dBB3UZ2D+6oiIjr8=\",\n" +
				"    \"org.example.customfield\": 42\n" +
				"}";
		UVFMasterkey masterkey = UVFMasterkey.fromDecryptedPayload(json);

		Assertions.assertEquals(473544690, masterkey.initialSeed);
		Assertions.assertEquals(1075513622, masterkey.latestSeed);
		Assertions.assertArrayEquals(Base64.getDecoder().decode("NIlr89R7FhochyP4yuXZmDqCnQ0dBB3UZ2D+6oiIjr8="), masterkey.kdfSalt);
		Assertions.assertArrayEquals(Base64.getDecoder().decode("ypeBEsobvcr6wjGzmiPcTaeG7/gUfE5yuYB3ha/uSLs="), masterkey.seeds.get(473544690));
		Assertions.assertArrayEquals(Base64.getDecoder().decode("Ln0sA6lQeuJl7PW1NWiFpTOTogKdJBOUmXJloaJa78Y="), masterkey.seeds.get(1075513622));
	}

	@Test
	public void testSubkey() {
		Map<Integer, byte[]> seeds = Collections.singletonMap(-1540072521, Base64.getDecoder().decode("fP4V4oAjsUw5DqackAvLzA0oP1kAQZ0f5YFZQviXSuU="));
		byte[] kdfSalt =  Base64.getDecoder().decode("HE4OP+2vyfLLURicF1XmdIIsWv0Zs6MobLKROUIEhQY=");
		try (UVFMasterkey masterkey = new UVFMasterkey(seeds, kdfSalt, -1540072521, -1540072521)) {
			try (DestroyableSecretKey subkey = masterkey.subKey(-1540072521, 32, "fileHeader".getBytes(StandardCharsets.US_ASCII), "AES")) {
				Assertions.assertEquals("PwnW2t/pK9dmzc+GTLdBSaB8ilcwsTq4sYOeiyo3cpU=", Base64.getEncoder().encodeToString(subkey.getEncoded()));
			}
		}
	}

}