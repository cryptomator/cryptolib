package org.cryptomator.cryptolib.api;

import org.cryptomator.cryptolib.common.DestroyableSecretKey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

class UVFMasterkeyTest {

	// example payload from the UVF spec (vault metadata/README.md), whose seed IDs are derived from the seeds
	private static final String SPEC_PAYLOAD = "{\n" +
			"    \"fileFormat\": \"AES-256-GCM-32k\",\n" +
			"    \"nameFormat\": \"AES-SIV-512-B64URL\",\n" +
			"    \"seeds\": {\n" +
			"        \"DU3kfQ\": \"ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs\",\n" +
			"        \"YuRlmw\": \"PiPoFgA5WUoziU9lZOGxNIu9egCI1CxKy3PurtWcAJ0\",\n" +
			"        \"q8ZMqw\": \"Ln0sA6lQeuJl7PW1NWiFpTOTogKdJBOUmXJloaJa78Y\"\n" +
			"    },\n" +
			"    \"initialSeed\": \"DU3kfQ\",\n" +
			"    \"latestSeed\": \"q8ZMqw\",\n" +
			"    \"kdf\": \"HKDF-SHA512\",\n" +
			"    \"kdfSalt\": \"NIlr89R7FhochyP4yuXZmDqCnQ0dBB3UZ2D-6oiIjr8\",\n" +
			"    \"recipientDetails\": {\n" +
			"        \"com.example.vaultpassword\": { \"alg\": \"PBES2-HS512+A256KW\" }\n" +
			"    },\n" +
			"    \"org.example.customfield\": 42\n" +
			"}";

	private static final byte[] TEST_SEED = Base64.getUrlDecoder().decode("fP4V4oAjsUw5DqackAvLzA0oP1kAQZ0f5YFZQviXSuU");
	private static final byte[] TEST_KDF_SALT = Base64.getUrlDecoder().decode("HE4OP-2vyfLLURicF1XmdIIsWv0Zs6MobLKROUIEhQY");
	private static final int TEST_SEED_ID = 1925996179; // "csxekw"

	@Test
	@DisplayName("parse the spec's example payload")
	public void testFromDecryptedPayload() {
		UVFMasterkey masterkey = UVFMasterkey.fromDecryptedPayload(SPEC_PAYLOAD);

		Assertions.assertEquals(seedId("DU3kfQ"), masterkey.initialSeed);
		Assertions.assertEquals(seedId("q8ZMqw"), masterkey.latestSeed);
		Assertions.assertArrayEquals(Base64.getUrlDecoder().decode("NIlr89R7FhochyP4yuXZmDqCnQ0dBB3UZ2D-6oiIjr8"), masterkey.kdfSalt);
		Assertions.assertEquals(3, masterkey.seeds.size());
		Assertions.assertArrayEquals(Base64.getUrlDecoder().decode("ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs"), masterkey.seeds.get(seedId("DU3kfQ")));
		Assertions.assertArrayEquals(Base64.getUrlDecoder().decode("PiPoFgA5WUoziU9lZOGxNIu9egCI1CxKy3PurtWcAJ0"), masterkey.seeds.get(seedId("YuRlmw")));
		Assertions.assertArrayEquals(Base64.getUrlDecoder().decode("Ln0sA6lQeuJl7PW1NWiFpTOTogKdJBOUmXJloaJa78Y"), masterkey.seeds.get(seedId("q8ZMqw")));
	}

	@DisplayName("reject invalid payloads")
	@ParameterizedTest(name = "{0}")
	@CsvSource(delimiter = '|', value = {
			"seed ID not derived from seed | \"DU3kfQ\": \"ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs\" | \"DU3kfg\": \"ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs\"",
			"seed too short | \"DU3kfQ\": \"ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs\" | \"DU3kfQ\": \"ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSA\"",
			"padded seed | \"DU3kfQ\": \"ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs\" | \"DU3kfQ\": \"ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs=\"",
			"padded seed ID | \"DU3kfQ\": \"ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs\" | \"DU3kfQ==\": \"ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs\"",
			"non-canonical seed ID | \"DU3kfQ\": \"ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs\" | \"DU3kfR\": \"ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs\"",
			"missing latest seed | \"q8ZMqw\": \"Ln0sA6lQeuJl7PW1NWiFpTOTogKdJBOUmXJloaJa78Y\" | \"YuRlmw\": \"PiPoFgA5WUoziU9lZOGxNIu9egCI1CxKy3PurtWcAJ0\"",
			"missing initial seed | \"DU3kfQ\": \"ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs\" | \"YuRlmw\": \"PiPoFgA5WUoziU9lZOGxNIu9egCI1CxKy3PurtWcAJ0\"",
			"short kdfSalt | \"kdfSalt\": \"NIlr89R7FhochyP4yuXZmDqCnQ0dBB3UZ2D-6oiIjr8\" | \"kdfSalt\": \"NIlr89R7FhochyP4yuXZmDqCnQ0dBB3UZ2D-6oiIjg\"",
			"unsupported fileFormat | \"AES-256-GCM-32k\" | \"AES-256-GCM-64k\"",
			"unsupported nameFormat | \"AES-SIV-512-B64URL\" | \"AES-SIV-512-B32\"",
			"unsupported kdf | \"HKDF-SHA512\" | \"HKDF-SHA256\"",
	})
	public void testFromInvalidPayload(String description, String original, String replacement) {
		String json = SPEC_PAYLOAD.replace(original, replacement);
		Assertions.assertNotEquals(SPEC_PAYLOAD, json);
		Assertions.assertThrows(IllegalArgumentException.class, () -> UVFMasterkey.fromDecryptedPayload(json));
	}

	@Test
	@DisplayName("reject empty seeds")
	public void testFromPayloadWithoutSeeds() {
		String json = SPEC_PAYLOAD.replaceAll("(?s)\"seeds\": \\{.*?\\},", "\"seeds\": {},");
		Assertions.assertNotEquals(SPEC_PAYLOAD, json);
		Assertions.assertThrows(IllegalArgumentException.class, () -> UVFMasterkey.fromDecryptedPayload(json));
	}

	@Test
	@DisplayName("seed digest and ID derivation")
	public void testSeedDigest() {
		byte[] kdfSalt = Base64.getUrlDecoder().decode("NIlr89R7FhochyP4yuXZmDqCnQ0dBB3UZ2D-6oiIjr8");
		byte[] seed = Base64.getUrlDecoder().decode("ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs");

		byte[] digest = UVFMasterkey.seedDigest(kdfSalt, seed);

		Assertions.assertEquals(32, digest.length);
		Assertions.assertEquals("DU3kfVOrwkeRcIiR7x6ptvokoTs5IQ7HDJX2ZXgXVOk", Base64.getUrlEncoder().withoutPadding().encodeToString(digest));
		Assertions.assertEquals(seedId("DU3kfQ"), UVFMasterkey.seedId(kdfSalt, seed));
		Assertions.assertEquals(TEST_SEED_ID, UVFMasterkey.seedId(TEST_KDF_SALT, TEST_SEED));
	}

	@Test
	@DisplayName("seed digests of all seeds for pinning")
	public void testSeedDigests() {
		UVFMasterkey masterkey = UVFMasterkey.fromDecryptedPayload(SPEC_PAYLOAD);

		Map<Integer, byte[]> digests = masterkey.seedDigests();

		Assertions.assertEquals(3, digests.size());
		for (Map.Entry<Integer, byte[]> entry : digests.entrySet()) {
			Assertions.assertEquals(32, entry.getValue().length);
			Assertions.assertEquals(entry.getKey(), ByteBuffer.wrap(entry.getValue()).getInt(), "digest starts with the seed ID");
		}
		Assertions.assertEquals("q8ZMq41_k1bsnYd2Dl3QsW5HST63TEoN4RtThwDy34c", Base64.getUrlEncoder().withoutPadding().encodeToString(digests.get(seedId("q8ZMqw"))));
	}

	@Test
	@DisplayName("constructor validates seed IDs")
	public void testConstructorWithWrongSeedId() {
		Map<Integer, byte[]> seeds = Collections.singletonMap(TEST_SEED_ID + 1, TEST_SEED);
		Assertions.assertThrows(IllegalArgumentException.class, () -> new UVFMasterkey(seeds, TEST_KDF_SALT, TEST_SEED_ID + 1, TEST_SEED_ID + 1));
	}

	@Test
	@DisplayName("constructor validates initial and latest seed")
	public void testConstructorWithUnknownLatestSeed() {
		Map<Integer, byte[]> seeds = Collections.singletonMap(TEST_SEED_ID, TEST_SEED);
		Assertions.assertThrows(IllegalArgumentException.class, () -> new UVFMasterkey(seeds, TEST_KDF_SALT, TEST_SEED_ID, 0xBAD5EED));
		Assertions.assertThrows(IllegalArgumentException.class, () -> new UVFMasterkey(seeds, TEST_KDF_SALT, 0xBAD5EED, TEST_SEED_ID));
	}

	@Test
	@DisplayName("constructor validates salt length")
	public void testConstructorWithShortSalt() {
		Map<Integer, byte[]> seeds = Collections.singletonMap(TEST_SEED_ID, TEST_SEED);
		Assertions.assertThrows(IllegalArgumentException.class, () -> new UVFMasterkey(seeds, new byte[16], TEST_SEED_ID, TEST_SEED_ID));
	}

	@Test
	public void testSubkey() {
		Map<Integer, byte[]> seeds = Collections.singletonMap(TEST_SEED_ID, TEST_SEED);
		try (UVFMasterkey masterkey = new UVFMasterkey(seeds, TEST_KDF_SALT, TEST_SEED_ID, TEST_SEED_ID)) {
			try (DestroyableSecretKey subkey = masterkey.subKey(TEST_SEED_ID, 32, "fileHeader".getBytes(StandardCharsets.US_ASCII), "AES")) {
				Assertions.assertEquals("PwnW2t/pK9dmzc+GTLdBSaB8ilcwsTq4sYOeiyo3cpU=", Base64.getEncoder().encodeToString(subkey.getEncoded()));
			}
		}
	}

	@Test
	public void testRootDirId() {
		Map<Integer, byte[]> seeds = Collections.singletonMap(TEST_SEED_ID, TEST_SEED);
		try (UVFMasterkey masterkey = new UVFMasterkey(seeds, TEST_KDF_SALT, TEST_SEED_ID, TEST_SEED_ID)) {
			Assertions.assertEquals("24UBEDeGu5taq7U4GqyA0MXUXb9HTYS6p3t9vvHGJAc=", Base64.getEncoder().encodeToString(masterkey.rootDirId()));
		}
	}

	@Test
	public void testDestroy() {
		Map<Integer, byte[]> seeds = new HashMap<>();
		seeds.put(TEST_SEED_ID, TEST_SEED.clone());
		UVFMasterkey masterkey = new UVFMasterkey(seeds, TEST_KDF_SALT.clone(), TEST_SEED_ID, TEST_SEED_ID);

		masterkey.destroy();

		Assertions.assertTrue(masterkey.isDestroyed());
		Assertions.assertThrows(IllegalStateException.class, masterkey::seedDigests);
	}

	private static int seedId(String base64url) {
		return ByteBuffer.wrap(Base64.getUrlDecoder().decode(base64url)).getInt();
	}

}
