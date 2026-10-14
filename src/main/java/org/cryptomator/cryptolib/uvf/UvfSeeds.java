package org.cryptomator.cryptolib.uvf;

import com.google.common.base.Preconditions;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSyntaxException;
import org.cryptomator.cryptolib.api.VaultConfigLoadException;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;
import org.cryptomator.cryptolib.common.HKDFHelper;
import org.jspecify.annotations.Nullable;

import javax.security.auth.Destroyable;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * The decrypted payload of {@code vault.uvf}: the vault's seeds, KDF salt and formats, plus any fields cryptolib does not interpret.
 */
final class UvfSeeds implements Destroyable, AutoCloseable {

	private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
	private static final Base64.Decoder B64_DECODER = Base64.getUrlDecoder();
	private static final Set<String> KNOWN_FIELDS = new HashSet<>(Arrays.asList("fileFormat", "nameFormat", "seeds", "initialSeed", "latestSeed", "kdf", "kdfSalt"));

	private final Map<Integer, byte[]> seeds = new LinkedHashMap<>();
	private final byte[] kdfSalt;
	private final int initialSeedId;
	private int latestSeedId;
	private final Map<String, JsonElement> customFields;
	private boolean destroyed = false;

	UvfSeeds(Map<Integer, byte[]> seeds, byte[] kdfSalt, int initialSeedId, int latestSeedId, Map<String, JsonElement> customFields) {
		Preconditions.checkArgument(kdfSalt.length == Constants.KDF_SALT_LEN, "kdfSalt must be %s bytes", Constants.KDF_SALT_LEN);
		Preconditions.checkArgument(seeds.containsKey(initialSeedId), "initialSeed not among seeds");
		Preconditions.checkArgument(seeds.containsKey(latestSeedId), "latestSeed not among seeds");
		for (Map.Entry<Integer, byte[]> entry : seeds.entrySet()) {
			Preconditions.checkArgument(entry.getValue().length == Constants.SEED_LEN, "seed must be %s bytes", Constants.SEED_LEN);
			this.seeds.put(entry.getKey(), entry.getValue().clone());
		}
		this.kdfSalt = kdfSalt.clone();
		this.initialSeedId = initialSeedId;
		this.latestSeedId = latestSeedId;
		this.customFields = new LinkedHashMap<>(customFields);
	}

	/**
	 * @param csprng Source of randomness
	 * @return Seeds for a new vault: a fresh salt and one seed
	 */
	static UvfSeeds create(SecureRandom csprng) {
		byte[] kdfSalt = new byte[Constants.KDF_SALT_LEN];
		csprng.nextBytes(kdfSalt);
		byte[] seed = new byte[Constants.SEED_LEN];
		csprng.nextBytes(seed);
		try {
			int seedId = randomSeedId(csprng, Collections.<Integer>emptySet());
			return new UvfSeeds(Collections.singletonMap(seedId, seed), kdfSalt, seedId, seedId, Collections.<String, JsonElement>emptyMap());
		} finally {
			Arrays.fill(seed, (byte) 0x00);
			Arrays.fill(kdfSalt, (byte) 0x00);
		}
	}

	/**
	 * @param json The decrypted JWE payload
	 * @return The parsed seeds
	 * @throws VaultConfigLoadException If the payload is malformed or declares unsupported formats
	 */
	static UvfSeeds fromDecryptedPayload(String json) throws VaultConfigLoadException {
		try {
			JsonObject root = JsonParser.parseString(json).getAsJsonObject();
			requireFormat(root, "fileFormat", Constants.FILE_FORMAT);
			requireFormat(root, "nameFormat", Constants.NAME_FORMAT);
			requireFormat(root, "kdf", Constants.KDF);
			byte[] kdfSalt = B64_DECODER.decode(requireString(root, "kdfSalt"));
			int initialSeed = decodeSeedId(requireString(root, "initialSeed"));
			int latestSeed = decodeSeedId(requireString(root, "latestSeed"));
			JsonElement seedsElement = root.get("seeds");
			if (seedsElement == null || !seedsElement.isJsonObject()) {
				throw new VaultConfigLoadException("Missing or invalid field: seeds");
			}
			Map<Integer, byte[]> seeds = new LinkedHashMap<>();
			for (Map.Entry<String, JsonElement> entry : seedsElement.getAsJsonObject().entrySet()) {
				seeds.put(decodeSeedId(entry.getKey()), B64_DECODER.decode(entry.getValue().getAsString()));
			}
			Map<String, JsonElement> customFields = new LinkedHashMap<>();
			for (Map.Entry<String, JsonElement> entry : root.entrySet()) {
				if (!KNOWN_FIELDS.contains(entry.getKey())) {
					customFields.put(entry.getKey(), entry.getValue());
				}
			}
			return new UvfSeeds(seeds, kdfSalt, initialSeed, latestSeed, customFields);
		} catch (JsonSyntaxException | IllegalStateException | IllegalArgumentException | UnsupportedOperationException e) {
			throw new VaultConfigLoadException("Malformed vault metadata", e);
		}
	}

	private static void requireFormat(JsonObject root, String field, String expected) throws VaultConfigLoadException {
		String actual = requireString(root, field);
		if (!expected.equals(actual)) {
			throw new VaultConfigLoadException("Unsupported " + field + ": " + actual);
		}
	}

	private static String requireString(JsonObject root, String field) throws VaultConfigLoadException {
		JsonElement element = root.get(field);
		if (element == null || !element.isJsonPrimitive() || !element.getAsJsonPrimitive().isString()) {
			throw new VaultConfigLoadException("Missing or invalid field: " + field);
		}
		return element.getAsString();
	}

	/**
	 * @return The JSON payload to encrypt into {@code vault.uvf}
	 */
	String toDecryptedPayload() {
		assertNotDestroyed();
		JsonObject root = new JsonObject();
		root.addProperty("fileFormat", Constants.FILE_FORMAT);
		root.addProperty("nameFormat", Constants.NAME_FORMAT);
		JsonObject seedsObject = new JsonObject();
		for (Map.Entry<Integer, byte[]> entry : seeds.entrySet()) {
			seedsObject.addProperty(encodeSeedId(entry.getKey()), B64.encodeToString(entry.getValue()));
		}
		root.add("seeds", seedsObject);
		root.addProperty("initialSeed", encodeSeedId(initialSeedId));
		root.addProperty("latestSeed", encodeSeedId(latestSeedId));
		root.addProperty("kdf", Constants.KDF);
		root.addProperty("kdfSalt", B64.encodeToString(kdfSalt));
		for (Map.Entry<String, JsonElement> entry : customFields.entrySet()) {
			root.add(entry.getKey(), entry.getValue());
		}
		return root.toString();
	}

	static int decodeSeedId(String base64url) {
		byte[] bytes = B64_DECODER.decode(base64url);
		Preconditions.checkArgument(bytes.length == Constants.SEED_ID_LEN, "seed id must be %s bytes", Constants.SEED_ID_LEN);
		return ByteBuffer.wrap(bytes).getInt();
	}

	static String encodeSeedId(int seedId) {
		return B64.encodeToString(ByteBuffer.allocate(Constants.SEED_ID_LEN).putInt(seedId).array());
	}

	private static int randomSeedId(SecureRandom csprng, Set<Integer> taken) {
		byte[] idBytes = new byte[Constants.SEED_ID_LEN];
		int id;
		do {
			csprng.nextBytes(idBytes);
			id = ByteBuffer.wrap(idBytes).getInt();
		} while (taken.contains(id));
		return id;
	}

	int initialSeedId() {
		return initialSeedId;
	}

	int latestSeedId() {
		return latestSeedId;
	}

	Set<Integer> seedIds() {
		return Collections.unmodifiableSet(new TreeSet<>(seeds.keySet()));
	}

	boolean hasSeed(int seedId) {
		return seeds.containsKey(seedId);
	}

	/**
	 * @return Unknown payload fields as plain Java objects (String, Long, Double, Boolean, List, Map, null)
	 */
	Map<String, @Nullable Object> customFields() {
		Map<String, @Nullable Object> result = new LinkedHashMap<>();
		for (Map.Entry<String, JsonElement> entry : customFields.entrySet()) {
			result.put(entry.getKey(), toJavaObject(entry.getValue()));
		}
		return Collections.unmodifiableMap(result);
	}

	private static @Nullable Object toJavaObject(JsonElement element) {
		if (element.isJsonNull()) {
			return null;
		} else if (element.isJsonPrimitive()) {
			JsonPrimitive primitive = element.getAsJsonPrimitive();
			if (primitive.isBoolean()) {
				return primitive.getAsBoolean();
			} else if (primitive.isNumber()) {
				String number = primitive.getAsString();
				if (number.contains(".") || number.contains("e") || number.contains("E")) {
					return primitive.getAsDouble();
				} else {
					return primitive.getAsLong();
				}
			} else {
				return primitive.getAsString();
			}
		} else if (element.isJsonArray()) {
			List<Object> list = new ArrayList<>();
			for (JsonElement child : element.getAsJsonArray()) {
				list.add(toJavaObject(child));
			}
			return Collections.unmodifiableList(list);
		} else {
			Map<String, Object> map = new LinkedHashMap<>();
			for (Map.Entry<String, JsonElement> entry : element.getAsJsonObject().entrySet()) {
				map.put(entry.getKey(), toJavaObject(entry.getValue()));
			}
			return Collections.unmodifiableMap(map);
		}
	}

	/**
	 * Adds a fresh random seed and makes it the latest one.
	 *
	 * @param csprng Source of randomness
	 * @return The new seed's id
	 */
	int addSeed(SecureRandom csprng) {
		assertNotDestroyed();
		byte[] seed = new byte[Constants.SEED_LEN];
		csprng.nextBytes(seed);
		int seedId = randomSeedId(csprng, seeds.keySet());
		seeds.put(seedId, seed);
		latestSeedId = seedId;
		return seedId;
	}

	/**
	 * Derives a subkey from a seed.
	 *
	 * @param seedId Which seed to derive from
	 * @param length Desired key length in bytes
	 * @param context Usage context, distinguishing subkeys of the same seed
	 * @param algorithm The {@link javax.crypto.SecretKey#getAlgorithm() algorithm} of the resulting key
	 * @return The subkey
	 * @throws IllegalArgumentException If no seed with the given id exists
	 */
	DestroyableSecretKey subKey(int seedId, int length, byte[] context, String algorithm) {
		assertNotDestroyed();
		byte[] seed = seeds.get(seedId);
		if (seed == null) {
			throw new IllegalArgumentException("Unknown seed id " + seedId);
		}
		byte[] subkey = HKDFHelper.hkdfSha512(kdfSalt, seed, context, length);
		try {
			return new DestroyableSecretKey(subkey, algorithm);
		} finally {
			Arrays.fill(subkey, (byte) 0x00);
		}
	}

	/**
	 * @return The root directory's id, derived from the initial seed
	 */
	byte[] rootDirId() {
		assertNotDestroyed();
		return HKDFHelper.hkdfSha512(kdfSalt, seeds.get(initialSeedId), Constants.KDF_CONTEXT_ROOT_DIR_ID, Constants.DIR_ID_LEN);
	}

	@Override
	public boolean isDestroyed() {
		return destroyed;
	}

	@Override
	public void destroy() {
		for (byte[] seed : seeds.values()) {
			Arrays.fill(seed, (byte) 0x00);
		}
		seeds.clear();
		Arrays.fill(kdfSalt, (byte) 0x00);
		destroyed = true;
	}

	@Override
	public void close() {
		destroy();
	}

	private void assertNotDestroyed() {
		if (destroyed) {
			throw new IllegalStateException("Seeds destroyed");
		}
	}

}
