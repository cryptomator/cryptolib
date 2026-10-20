package org.cryptomator.cryptolib.uvf;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import org.cryptomator.cryptolib.api.VaultConfigLoadException;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;
import org.cryptomator.cryptolib.common.SecureRandomMock;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;

class UvfSeedsTest {

	// example payload from the UVF specification (vault metadata/README.md)
	static final String SPEC_PAYLOAD = "{\n" //
			+ "    \"fileFormat\": \"AES-256-GCM-32k\",\n" //
			+ "    \"nameFormat\": \"AES-SIV-512-B64URL\",\n" //
			+ "    \"seeds\": {\n" //
			+ "        \"HDm38i\": \"ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs\",\n" //
			+ "        \"gBryKw\": \"PiPoFgA5WUoziU9lZOGxNIu9egCI1CxKy3PurtWcAJ0\",\n" //
			+ "        \"QBsJFo\": \"Ln0sA6lQeuJl7PW1NWiFpTOTogKdJBOUmXJloaJa78Y\"\n" //
			+ "    },\n" //
			+ "    \"initialSeed\": \"HDm38i\",\n" //
			+ "    \"latestSeed\": \"QBsJFo\",\n" //
			+ "    \"kdf\": \"HKDF-SHA512\",\n" //
			+ "    \"kdfSalt\": \"NIlr89R7FhochyP4yuXZmDqCnQ0dBB3UZ2D-6oiIjr8\",\n" //
			+ "    \"org.example.customfield\": 42\n" //
			+ "}";

	static final int TEST_SEED_ID = -1540072521;
	static final Map<Integer, byte[]> TEST_SEEDS = Collections.singletonMap(TEST_SEED_ID, Base64.getUrlDecoder().decode("fP4V4oAjsUw5DqackAvLzA0oP1kAQZ0f5YFZQviXSuU"));
	static final byte[] TEST_KDF_SALT = Base64.getUrlDecoder().decode("HE4OP-2vyfLLURicF1XmdIIsWv0Zs6MobLKROUIEhQY");

	static UvfSeeds testSeeds() {
		return new UvfSeeds(TEST_SEEDS, TEST_KDF_SALT, TEST_SEED_ID, TEST_SEED_ID, Collections.<String, JsonElement>emptyMap());
	}

	@Test
	@DisplayName("parse spec example payload")
	void testFromDecryptedPayload() {
		UvfSeeds seeds = UvfSeeds.fromDecryptedPayload(SPEC_PAYLOAD);
		Assertions.assertEquals(473544690, seeds.initialSeedId());
		Assertions.assertEquals(1075513622, seeds.latestSeedId());
		Assertions.assertEquals(3, seeds.seedIds().size());
		Assertions.assertTrue(seeds.hasSeed(UvfSeeds.decodeSeedId("gBryKw")));
		Assertions.assertEquals(Collections.singletonMap("org.example.customfield", 42L), seeds.customFields());
	}

	@Test
	@DisplayName("serialize preserves everything incl. custom fields")
	void testRoundTrip() {
		UvfSeeds seeds = UvfSeeds.fromDecryptedPayload(SPEC_PAYLOAD);
		String json = seeds.toDecryptedPayload();
		// the spec example uses non-canonical base64url seed ids ("HDm38i" has non-zero trailing bits), we re-emit canonical ones ("HDm38g"):
		String canonicalSpecPayload = SPEC_PAYLOAD.replace("HDm38i", "HDm38g").replace("QBsJFo", "QBsJFg");
		Assertions.assertEquals(JsonParser.parseString(canonicalSpecPayload), JsonParser.parseString(json));
		UvfSeeds reparsed = UvfSeeds.fromDecryptedPayload(json);
		Assertions.assertEquals(seeds.initialSeedId(), reparsed.initialSeedId());
		Assertions.assertEquals(seeds.latestSeedId(), reparsed.latestSeedId());
		Assertions.assertEquals(seeds.seedIds(), reparsed.seedIds());
		Assertions.assertArrayEquals(seeds.rootDirId(), reparsed.rootDirId());
		Assertions.assertEquals(seeds.customFields(), reparsed.customFields());
	}

	@Test
	@DisplayName("seed id encoding")
	void testSeedIdEncoding() {
		Assertions.assertEquals(473544690, UvfSeeds.decodeSeedId("HDm38i")); // non-canonical trailing bits are tolerated
		Assertions.assertEquals(473544690, UvfSeeds.decodeSeedId("HDm38g"));
		Assertions.assertEquals("HDm38g", UvfSeeds.encodeSeedId(473544690));
		Assertions.assertEquals("pDRbtw", UvfSeeds.encodeSeedId(TEST_SEED_ID));
		Assertions.assertThrows(IllegalArgumentException.class, () -> UvfSeeds.decodeSeedId("HDm3"));
	}

	@Test
	@DisplayName("subkey derivation vector")
	void testSubkey() {
		try (UvfSeeds seeds = testSeeds(); DestroyableSecretKey subkey = seeds.subKey(TEST_SEED_ID, 32, "fileHeader".getBytes(StandardCharsets.US_ASCII), "AES")) {
			Assertions.assertEquals("PwnW2t/pK9dmzc+GTLdBSaB8ilcwsTq4sYOeiyo3cpU=", Base64.getEncoder().encodeToString(subkey.getEncoded()));
		}
	}

	@Test
	@DisplayName("root dir id vector")
	void testRootDirId() {
		try (UvfSeeds seeds = testSeeds()) {
			Assertions.assertEquals("24UBEDeGu5taq7U4GqyA0MXUXb9HTYS6p3t9vvHGJAc=", Base64.getEncoder().encodeToString(seeds.rootDirId()));
		}
		Assertions.assertEquals("5WEGzwKkAHPwVSjT2Brr3P3zLz7oMiNpMn/qBvht7eM=", Base64.getEncoder().encodeToString(UvfSeeds.fromDecryptedPayload(SPEC_PAYLOAD).rootDirId()));
	}

	@Test
	@DisplayName("unknown seed")
	void testUnknownSeed() {
		try (UvfSeeds seeds = testSeeds()) {
			Assertions.assertThrows(IllegalArgumentException.class, () -> seeds.subKey(42, 32, new byte[0], "AES"));
		}
	}

	@Test
	@DisplayName("add seed")
	void testAddSeed() {
		try (UvfSeeds seeds = testSeeds()) {
			int newId = seeds.addSeed(SecureRandomMock.PRNG_RANDOM);
			Assertions.assertNotEquals(TEST_SEED_ID, newId);
			Assertions.assertEquals(newId, seeds.latestSeedId());
			Assertions.assertEquals(TEST_SEED_ID, seeds.initialSeedId());
			Assertions.assertEquals(2, seeds.seedIds().size());
			UvfSeeds reparsed = UvfSeeds.fromDecryptedPayload(seeds.toDecryptedPayload());
			Assertions.assertEquals(newId, reparsed.latestSeedId());
			Assertions.assertArrayEquals(seeds.subKey(newId, 32, new byte[0], "AES").getEncoded(), reparsed.subKey(newId, 32, new byte[0], "AES").getEncoded());
		}
	}

	@Test
	@DisplayName("create")
	void testCreate() {
		try (UvfSeeds seeds = UvfSeeds.create(SecureRandomMock.PRNG_RANDOM)) {
			Assertions.assertEquals(seeds.initialSeedId(), seeds.latestSeedId());
			Assertions.assertEquals(1, seeds.seedIds().size());
			Assertions.assertTrue(seeds.customFields().isEmpty());
			Assertions.assertEquals(32, seeds.rootDirId().length);
		}
	}

	@Test
	@DisplayName("destroy")
	void testDestroy() {
		UvfSeeds seeds = testSeeds();
		seeds.destroy();
		Assertions.assertTrue(seeds.isDestroyed());
		Assertions.assertThrows(IllegalStateException.class, seeds::rootDirId);
	}

	@ParameterizedTest(name = "malformed payload is rejected: {0}")
	@ValueSource(strings = { //
			"not json", //
			"{}", //
			"{\"fileFormat\":\"AES-256-GCM-64k\",\"nameFormat\":\"AES-SIV-512-B64URL\",\"kdf\":\"HKDF-SHA512\",\"kdfSalt\":\"NIlr89R7FhochyP4yuXZmDqCnQ0dBB3UZ2D-6oiIjr8\",\"initialSeed\":\"HDm38i\",\"latestSeed\":\"HDm38i\",\"seeds\":{\"HDm38i\":\"ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs\"}}", //
			"{\"fileFormat\":\"AES-256-GCM-32k\",\"nameFormat\":\"AES-SIV-512-B64URL\",\"kdf\":\"HKDF-SHA512\",\"kdfSalt\":\"NIlr89R7FhochyP4yuXZmDqCnQ0dBB3UZ2D-6oiIjr8\",\"initialSeed\":\"HDm38i\",\"latestSeed\":\"QBsJFo\",\"seeds\":{\"HDm38i\":\"ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs\"}}", //
			"{\"fileFormat\":\"AES-256-GCM-32k\",\"nameFormat\":\"AES-SIV-512-B64URL\",\"kdf\":\"HKDF-SHA512\",\"kdfSalt\":\"short\",\"initialSeed\":\"HDm38i\",\"latestSeed\":\"HDm38i\",\"seeds\":{\"HDm38i\":\"ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs\"}}" //
	})
	void testMalformedPayload(String json) {
		Assertions.assertThrows(VaultConfigLoadException.class, () -> UvfSeeds.fromDecryptedPayload(json));
	}

}
