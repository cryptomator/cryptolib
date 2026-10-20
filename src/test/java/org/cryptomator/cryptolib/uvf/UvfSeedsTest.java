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
import java.util.LinkedHashMap;
import java.util.Map;

class UvfSeedsTest {

	// example payload from the UVF specification (vault metadata/README.md); seed ids are the first four bytes of kdf(seed, 32, "seedDigest")
	static final String SPEC_PAYLOAD = "{\n" //
			+ "    \"fileFormat\": \"AES-256-GCM-32k\",\n" //
			+ "    \"nameFormat\": \"AES-SIV-512-B64URL\",\n" //
			+ "    \"seeds\": {\n" //
			+ "        \"DU3kfQ\": \"ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs\",\n" //
			+ "        \"YuRlmw\": \"PiPoFgA5WUoziU9lZOGxNIu9egCI1CxKy3PurtWcAJ0\",\n" //
			+ "        \"q8ZMqw\": \"Ln0sA6lQeuJl7PW1NWiFpTOTogKdJBOUmXJloaJa78Y\"\n" //
			+ "    },\n" //
			+ "    \"initialSeed\": \"DU3kfQ\",\n" //
			+ "    \"latestSeed\": \"q8ZMqw\",\n" //
			+ "    \"kdf\": \"HKDF-SHA512\",\n" //
			+ "    \"kdfSalt\": \"NIlr89R7FhochyP4yuXZmDqCnQ0dBB3UZ2D-6oiIjr8\",\n" //
			+ "    \"recipientDetails\": {\n" //
			+ "        \"com.example.vaultpassword\": {\n" //
			+ "            \"alg\": \"PBES2-HS512+A256KW\"\n" //
			+ "        },\n" //
			+ "        \"com.example.userkey.42\": {\n" //
			+ "            \"alg\": \"ECDH-ES+A256KW\",\n" //
			+ "            \"jwk\": { \"kty\": \"OKP\", \"crv\": \"X25519\", \"x\": \"...\" }\n" //
			+ "        }\n" //
			+ "    },\n" //
			+ "    \"org.example.customfield\": 42\n" //
			+ "}";
	static final int SPEC_INITIAL_SEED_ID = 223208573; // DU3kfQ
	static final int SPEC_LATEST_SEED_ID = -1413067605; // q8ZMqw

	static final byte[] TEST_KDF_SALT = Base64.getUrlDecoder().decode("HE4OP-2vyfLLURicF1XmdIIsWv0Zs6MobLKROUIEhQY");
	static final byte[] TEST_SEED = Base64.getUrlDecoder().decode("fP4V4oAjsUw5DqackAvLzA0oP1kAQZ0f5YFZQviXSuU");
	static final int TEST_SEED_ID = 1925996179; // csxekw, derived from TEST_SEED
	static final Map<Integer, byte[]> TEST_SEEDS = Collections.singletonMap(TEST_SEED_ID, TEST_SEED);

	static UvfSeeds testSeeds() {
		return new UvfSeeds(TEST_SEEDS, TEST_KDF_SALT, TEST_SEED_ID, TEST_SEED_ID, Collections.<String, UvfSeeds.RecipientDetails>emptyMap(), Collections.<String, JsonElement>emptyMap());
	}

	@Test
	@DisplayName("seed ids are derived from the seeds (spec example and test seed)")
	void testSeedIdDerivation() {
		byte[] specSalt = Base64.getUrlDecoder().decode("NIlr89R7FhochyP4yuXZmDqCnQ0dBB3UZ2D-6oiIjr8");
		Assertions.assertEquals("DU3kfQ", UvfSeeds.encodeSeedId(UvfSeeds.seedId(specSalt, Base64.getUrlDecoder().decode("ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs"))));
		Assertions.assertEquals("YuRlmw", UvfSeeds.encodeSeedId(UvfSeeds.seedId(specSalt, Base64.getUrlDecoder().decode("PiPoFgA5WUoziU9lZOGxNIu9egCI1CxKy3PurtWcAJ0"))));
		Assertions.assertEquals("q8ZMqw", UvfSeeds.encodeSeedId(UvfSeeds.seedId(specSalt, Base64.getUrlDecoder().decode("Ln0sA6lQeuJl7PW1NWiFpTOTogKdJBOUmXJloaJa78Y"))));
		Assertions.assertEquals(TEST_SEED_ID, UvfSeeds.seedId(TEST_KDF_SALT, TEST_SEED));
		try (UvfSeeds seeds = testSeeds()) {
			Map<Integer, byte[]> digests = seeds.seedDigests();
			Assertions.assertEquals(Collections.singleton(TEST_SEED_ID), digests.keySet());
			Assertions.assertEquals("csxek3ZFh4n9SzxXwx4gnJCL0RlhriZHNa4fVAlGX4A", Base64.getUrlEncoder().withoutPadding().encodeToString(digests.get(TEST_SEED_ID)));
			Assertions.assertTrue(seeds.hasSeedWithDigest(digests.get(TEST_SEED_ID)));
			Assertions.assertFalse(seeds.hasSeedWithDigest(new byte[32]));
		}
		Assertions.assertThrows(IllegalArgumentException.class, () -> new UvfSeeds(Collections.singletonMap(42, TEST_SEED), TEST_KDF_SALT, 42, 42, Collections.<String, UvfSeeds.RecipientDetails>emptyMap(), Collections.<String, JsonElement>emptyMap()), "id must match the seed");
	}

	@Test
	@DisplayName("parse spec example payload")
	void testFromDecryptedPayload() {
		UvfSeeds seeds = UvfSeeds.fromDecryptedPayload(SPEC_PAYLOAD);
		Assertions.assertEquals(SPEC_INITIAL_SEED_ID, seeds.initialSeedId());
		Assertions.assertEquals(SPEC_LATEST_SEED_ID, seeds.latestSeedId());
		Assertions.assertEquals(3, seeds.seedIds().size());
		Assertions.assertTrue(seeds.hasSeed(UvfSeeds.decodeSeedId("YuRlmw")));
		Assertions.assertEquals(Collections.singletonMap("org.example.customfield", 42L), seeds.customFields());
		Map<String, UvfSeeds.RecipientDetails> details = seeds.recipientDetails();
		Assertions.assertEquals(2, details.size());
		Assertions.assertEquals("PBES2-HS512+A256KW", details.get("com.example.vaultpassword").alg);
		Assertions.assertNull(details.get("com.example.vaultpassword").jwk);
		Assertions.assertEquals("ECDH-ES+A256KW", details.get("com.example.userkey.42").alg);
		Assertions.assertEquals("X25519", details.get("com.example.userkey.42").jwk.get("crv"));
		Assertions.assertTrue(details.get("com.example.userkey.42").vendorFields.isEmpty());
	}

	@Test
	@DisplayName("serialize preserves everything incl. recipient details and custom fields")
	void testRoundTrip() {
		UvfSeeds seeds = UvfSeeds.fromDecryptedPayload(SPEC_PAYLOAD);
		String json = seeds.toDecryptedPayload();
		Assertions.assertEquals(JsonParser.parseString(SPEC_PAYLOAD), JsonParser.parseString(json));
		UvfSeeds reparsed = UvfSeeds.fromDecryptedPayload(json);
		Assertions.assertEquals(seeds.initialSeedId(), reparsed.initialSeedId());
		Assertions.assertEquals(seeds.latestSeedId(), reparsed.latestSeedId());
		Assertions.assertEquals(seeds.seedIds(), reparsed.seedIds());
		Assertions.assertArrayEquals(seeds.rootDirId(), reparsed.rootDirId());
		Assertions.assertEquals(seeds.customFields(), reparsed.customFields());
		Assertions.assertEquals(seeds.recipientDetails().keySet(), reparsed.recipientDetails().keySet());
	}

	@Test
	@DisplayName("recipient details with vendor fields round trip")
	void testRecipientDetails() {
		try (UvfSeeds seeds = testSeeds()) {
			Map<String, Object> vendorFields = new LinkedHashMap<>();
			vendorFields.put("org.example.salt", "AAAA");
			vendorFields.put("org.example.iterations", 3);
			seeds.putRecipient("org.example.key", new UvfSeeds.RecipientDetails("A256KW", null, vendorFields));
			UvfSeeds reparsed = UvfSeeds.fromDecryptedPayload(seeds.toDecryptedPayload());
			UvfSeeds.RecipientDetails details = reparsed.recipientDetails().get("org.example.key");
			Assertions.assertEquals("A256KW", details.alg);
			Assertions.assertEquals("AAAA", details.vendorFields.get("org.example.salt"));
			Assertions.assertEquals(3L, details.vendorFields.get("org.example.iterations"));
			seeds.removeRecipient("org.example.key");
			Assertions.assertTrue(seeds.recipientDetails().isEmpty());
		}
	}

	@Test
	@DisplayName("seed id encoding is strict")
	void testSeedIdEncoding() {
		Assertions.assertEquals(SPEC_INITIAL_SEED_ID, UvfSeeds.decodeSeedId("DU3kfQ"));
		Assertions.assertEquals("DU3kfQ", UvfSeeds.encodeSeedId(SPEC_INITIAL_SEED_ID));
		Assertions.assertEquals("csxekw", UvfSeeds.encodeSeedId(TEST_SEED_ID));
		Assertions.assertThrows(IllegalArgumentException.class, () -> UvfSeeds.decodeSeedId("DU3k"));
		Assertions.assertThrows(IllegalArgumentException.class, () -> UvfSeeds.decodeSeedId("DU3kfR"), "non-zero trailing bits");
		Assertions.assertThrows(IllegalArgumentException.class, () -> UvfSeeds.decodeSeedId("DU3kfQ=="), "padding");
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
	@DisplayName("add seed derives its id and redraws on collision")
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
		// a random source that first yields the existing seed (same id, same value: no-op) and then a different seed
		try (UvfSeeds seeds = testSeeds()) {
			int[] calls = {0};
			SecureRandomMock sameSeedFirst = new SecureRandomMock(bytes -> {
				if (calls[0]++ == 0) {
					System.arraycopy(TEST_SEED, 0, bytes, 0, bytes.length);
				} else {
					SecureRandomMock.PRNG_RANDOM.nextBytes(bytes);
				}
			});
			Assertions.assertEquals(TEST_SEED_ID, seeds.addSeed(sameSeedFirst), "re-adding the identical seed yields the identical entry");
			Assertions.assertEquals(1, seeds.seedIds().size());
		}
	}

	@Test
	@DisplayName("create")
	void testCreate() {
		try (UvfSeeds seeds = UvfSeeds.create(SecureRandomMock.PRNG_RANDOM)) {
			Assertions.assertEquals(seeds.initialSeedId(), seeds.latestSeedId());
			Assertions.assertEquals(1, seeds.seedIds().size());
			Assertions.assertTrue(seeds.customFields().isEmpty());
			Assertions.assertTrue(seeds.recipientDetails().isEmpty());
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
			// unsupported file format:
			"{\"fileFormat\":\"AES-256-GCM-64k\",\"nameFormat\":\"AES-SIV-512-B64URL\",\"kdf\":\"HKDF-SHA512\",\"kdfSalt\":\"NIlr89R7FhochyP4yuXZmDqCnQ0dBB3UZ2D-6oiIjr8\",\"initialSeed\":\"DU3kfQ\",\"latestSeed\":\"DU3kfQ\",\"seeds\":{\"DU3kfQ\":\"ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs\"},\"recipientDetails\":{}}", //
			// latestSeed unknown:
			"{\"fileFormat\":\"AES-256-GCM-32k\",\"nameFormat\":\"AES-SIV-512-B64URL\",\"kdf\":\"HKDF-SHA512\",\"kdfSalt\":\"NIlr89R7FhochyP4yuXZmDqCnQ0dBB3UZ2D-6oiIjr8\",\"initialSeed\":\"DU3kfQ\",\"latestSeed\":\"q8ZMqw\",\"seeds\":{\"DU3kfQ\":\"ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs\"},\"recipientDetails\":{}}", //
			// short salt:
			"{\"fileFormat\":\"AES-256-GCM-32k\",\"nameFormat\":\"AES-SIV-512-B64URL\",\"kdf\":\"HKDF-SHA512\",\"kdfSalt\":\"short\",\"initialSeed\":\"DU3kfQ\",\"latestSeed\":\"DU3kfQ\",\"seeds\":{\"DU3kfQ\":\"ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs\"},\"recipientDetails\":{}}", //
			// seed id not derived from the seed:
			"{\"fileFormat\":\"AES-256-GCM-32k\",\"nameFormat\":\"AES-SIV-512-B64URL\",\"kdf\":\"HKDF-SHA512\",\"kdfSalt\":\"NIlr89R7FhochyP4yuXZmDqCnQ0dBB3UZ2D-6oiIjr8\",\"initialSeed\":\"HDm38g\",\"latestSeed\":\"HDm38g\",\"seeds\":{\"HDm38g\":\"ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs\"},\"recipientDetails\":{}}", //
			// non-canonical seed id:
			"{\"fileFormat\":\"AES-256-GCM-32k\",\"nameFormat\":\"AES-SIV-512-B64URL\",\"kdf\":\"HKDF-SHA512\",\"kdfSalt\":\"NIlr89R7FhochyP4yuXZmDqCnQ0dBB3UZ2D-6oiIjr8\",\"initialSeed\":\"DU3kfR\",\"latestSeed\":\"DU3kfR\",\"seeds\":{\"DU3kfR\":\"ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs\"},\"recipientDetails\":{}}", //
			// no seeds:
			"{\"fileFormat\":\"AES-256-GCM-32k\",\"nameFormat\":\"AES-SIV-512-B64URL\",\"kdf\":\"HKDF-SHA512\",\"kdfSalt\":\"NIlr89R7FhochyP4yuXZmDqCnQ0dBB3UZ2D-6oiIjr8\",\"initialSeed\":\"DU3kfQ\",\"latestSeed\":\"DU3kfQ\",\"seeds\":{},\"recipientDetails\":{}}", //
			// missing recipientDetails:
			"{\"fileFormat\":\"AES-256-GCM-32k\",\"nameFormat\":\"AES-SIV-512-B64URL\",\"kdf\":\"HKDF-SHA512\",\"kdfSalt\":\"NIlr89R7FhochyP4yuXZmDqCnQ0dBB3UZ2D-6oiIjr8\",\"initialSeed\":\"DU3kfQ\",\"latestSeed\":\"DU3kfQ\",\"seeds\":{\"DU3kfQ\":\"ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs\"}}", //
			// recipient without alg:
			"{\"fileFormat\":\"AES-256-GCM-32k\",\"nameFormat\":\"AES-SIV-512-B64URL\",\"kdf\":\"HKDF-SHA512\",\"kdfSalt\":\"NIlr89R7FhochyP4yuXZmDqCnQ0dBB3UZ2D-6oiIjr8\",\"initialSeed\":\"DU3kfQ\",\"latestSeed\":\"DU3kfQ\",\"seeds\":{\"DU3kfQ\":\"ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs\"},\"recipientDetails\":{\"com.example.key\":{\"jwk\":{}}}}", //
			// recipient details not an object:
			"{\"fileFormat\":\"AES-256-GCM-32k\",\"nameFormat\":\"AES-SIV-512-B64URL\",\"kdf\":\"HKDF-SHA512\",\"kdfSalt\":\"NIlr89R7FhochyP4yuXZmDqCnQ0dBB3UZ2D-6oiIjr8\",\"initialSeed\":\"DU3kfQ\",\"latestSeed\":\"DU3kfQ\",\"seeds\":{\"DU3kfQ\":\"ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs\"},\"recipientDetails\":{\"com.example.key\":\"A256KW\"}}" //
	})
	void testMalformedPayload(String json) {
		Assertions.assertThrows(VaultConfigLoadException.class, () -> UvfSeeds.fromDecryptedPayload(json));
	}

}
