package org.cryptomator.cryptolib.uvf;

import com.google.gson.Gson;
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
 * The decrypted payload of {@code vault.uvf}: the vault's seeds, KDF salt, formats and recipient details, plus any fields cryptolib does not interpret.
 * <p>
 * Seed ids are derived from the seeds ({@code kdf(seed, 32, "seedDigest")[0..4]}) and verified on parsing.
 */
final class UvfSeeds implements Destroyable, AutoCloseable {

	private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
	private static final Base64.Decoder B64_DECODER = Base64.getUrlDecoder();
	private static final Gson GSON = new Gson();
	private static final Set<String> KNOWN_FIELDS = new HashSet<>(Arrays.asList("fileFormat", "nameFormat", "seeds", "initialSeed", "latestSeed", "kdf", "kdfSalt", Constants.RECIPIENT_DETAILS_FIELD));
	private static final String ALG_MEMBER = "alg";
	private static final String JWK_MEMBER = "jwk";

	/**
	 * One entry of the payload's {@code recipientDetails}: the recipient's key management algorithm, its public key for public-key algorithms, and vendor-specific members.
	 */
	static final class RecipientDetails {

		final String alg;
		final @Nullable Map<String, Object> jwk;
		final Map<String, Object> vendorFields;

		RecipientDetails(String alg, @Nullable Map<String, Object> jwk, Map<String, Object> vendorFields) {
			this.alg = alg;
			this.jwk = jwk == null ? null : Collections.unmodifiableMap(new LinkedHashMap<>(jwk));
			this.vendorFields = Collections.unmodifiableMap(new LinkedHashMap<>(vendorFields));
		}

	}

	private final Map<Integer, byte[]> seeds = new LinkedHashMap<>();
	private final byte[] kdfSalt;
	private final int initialSeedId;
	private int latestSeedId;
	private final Map<String, RecipientDetails> recipientDetails = new LinkedHashMap<>();
	private final Map<String, JsonElement> customFields;
	private boolean destroyed = false;

	UvfSeeds(Map<Integer, byte[]> seeds, byte[] kdfSalt, int initialSeedId, int latestSeedId, Map<String, RecipientDetails> recipientDetails, Map<String, JsonElement> customFields) {
		if (kdfSalt.length != Constants.KDF_SALT_LEN) {
			throw new IllegalArgumentException(String.format("kdfSalt must be %s bytes", Constants.KDF_SALT_LEN));
		}
		if (seeds.isEmpty()) {
			throw new IllegalArgumentException("No seeds");
		}
		if (!seeds.containsKey(initialSeedId)) {
			throw new IllegalArgumentException("initialSeed not among seeds");
		}
		if (!seeds.containsKey(latestSeedId)) {
			throw new IllegalArgumentException("latestSeed not among seeds");
		}
		this.kdfSalt = kdfSalt.clone();
		for (Map.Entry<Integer, byte[]> entry : seeds.entrySet()) {
			if (entry.getValue().length != Constants.SEED_LEN) {
				throw new IllegalArgumentException(String.format("seed must be %s bytes", Constants.SEED_LEN));
			}
			if (seedId(this.kdfSalt, entry.getValue()) != entry.getKey()) {
				throw new IllegalArgumentException("Seed id " + encodeSeedId(entry.getKey()) + " does not match its seed");
			}
			this.seeds.put(entry.getKey(), entry.getValue().clone());
		}
		this.initialSeedId = initialSeedId;
		this.latestSeedId = latestSeedId;
		this.recipientDetails.putAll(recipientDetails);
		this.customFields = new LinkedHashMap<>(customFields);
	}

	/**
	 * @param csprng Source of randomness
	 * @return Seeds for a new vault: a fresh salt and one seed, no recipients yet
	 */
	static UvfSeeds create(SecureRandom csprng) {
		byte[] kdfSalt = new byte[Constants.KDF_SALT_LEN];
		csprng.nextBytes(kdfSalt);
		byte[] seed = new byte[Constants.SEED_LEN];
		csprng.nextBytes(seed);
		try {
			int seedId = seedId(kdfSalt, seed);
			return new UvfSeeds(Collections.singletonMap(seedId, seed), kdfSalt, seedId, seedId, Collections.<String, RecipientDetails>emptyMap(), Collections.<String, JsonElement>emptyMap());
		} finally {
			Arrays.fill(seed, (byte) 0x00);
			Arrays.fill(kdfSalt, (byte) 0x00);
		}
	}

	/**
	 * @param kdfSalt The vault's KDF salt
	 * @param seed A seed
	 * @return The seed's id: the first four bytes of its digest as big endian integer
	 */
	static int seedId(byte[] kdfSalt, byte[] seed) {
		byte[] digest = seedDigest(kdfSalt, seed);
		try {
			return ByteBuffer.wrap(digest).getInt();
		} finally {
			Arrays.fill(digest, (byte) 0x00);
		}
	}

	private static byte[] seedDigest(byte[] kdfSalt, byte[] seed) {
		return HKDFHelper.hkdfSha512(kdfSalt, seed, Constants.KDF_CONTEXT_SEED_DIGEST, Constants.SEED_DIGEST_LEN);
	}

	/**
	 * @param json The decrypted JWE payload
	 * @return The parsed seeds
	 * @throws VaultConfigLoadException If the payload is malformed, declares unsupported formats, or a seed id does not match its seed
	 */
	static UvfSeeds fromDecryptedPayload(String json) throws VaultConfigLoadException {
		try {
			JsonObject root = JsonParser.parseString(json).getAsJsonObject();
			requireFormat(root, "fileFormat", Constants.FILE_FORMAT);
			requireFormat(root, "nameFormat", Constants.NAME_FORMAT);
			requireFormat(root, "kdf", Constants.KDF);
			byte[] kdfSalt = decodeStrict(requireString(root, "kdfSalt"));
			int initialSeed = decodeSeedId(requireString(root, "initialSeed"));
			int latestSeed = decodeSeedId(requireString(root, "latestSeed"));
			Map<Integer, byte[]> seeds = new LinkedHashMap<>();
			for (Map.Entry<String, JsonElement> entry : requireObject(root, "seeds").entrySet()) {
				seeds.put(decodeSeedId(entry.getKey()), decodeStrict(entry.getValue().getAsString()));
			}
			Map<String, RecipientDetails> recipientDetails = new LinkedHashMap<>();
			for (Map.Entry<String, JsonElement> entry : requireObject(root, Constants.RECIPIENT_DETAILS_FIELD).entrySet()) {
				recipientDetails.put(entry.getKey(), parseRecipientDetails(entry.getKey(), entry.getValue()));
			}
			Map<String, JsonElement> customFields = new LinkedHashMap<>();
			for (Map.Entry<String, JsonElement> entry : root.entrySet()) {
				if (!KNOWN_FIELDS.contains(entry.getKey())) {
					customFields.put(entry.getKey(), entry.getValue());
				}
			}
			return new UvfSeeds(seeds, kdfSalt, initialSeed, latestSeed, recipientDetails, customFields);
		} catch (JsonSyntaxException | IllegalStateException | IllegalArgumentException | UnsupportedOperationException | NullPointerException e) {
			throw new VaultConfigLoadException("Malformed vault metadata", e);
		}
	}

	@SuppressWarnings("unchecked")
	private static RecipientDetails parseRecipientDetails(String kid, JsonElement element) throws VaultConfigLoadException {
		if (!element.isJsonObject()) {
			throw new VaultConfigLoadException("Invalid recipient details for " + kid);
		}
		JsonObject object = element.getAsJsonObject();
		String alg = requireString(object, ALG_MEMBER);
		Map<String, Object> jwk = null;
		if (object.has(JWK_MEMBER)) {
			Object parsed = toJavaObject(object.get(JWK_MEMBER));
			if (!(parsed instanceof Map)) {
				throw new VaultConfigLoadException("Invalid jwk in recipient details for " + kid);
			}
			jwk = (Map<String, Object>) parsed;
		}
		Map<String, Object> vendorFields = new LinkedHashMap<>();
		for (Map.Entry<String, JsonElement> member : object.entrySet()) {
			if (!ALG_MEMBER.equals(member.getKey()) && !JWK_MEMBER.equals(member.getKey())) {
				vendorFields.put(member.getKey(), toJavaObject(member.getValue()));
			}
		}
		return new RecipientDetails(alg, jwk, vendorFields);
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

	private static JsonObject requireObject(JsonObject root, String field) throws VaultConfigLoadException {
		JsonElement element = root.get(field);
		if (element == null || !element.isJsonObject()) {
			throw new VaultConfigLoadException("Missing or invalid field: " + field);
		}
		return element.getAsJsonObject();
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
		JsonObject detailsObject = new JsonObject();
		for (Map.Entry<String, RecipientDetails> entry : recipientDetails.entrySet()) {
			JsonObject details = new JsonObject();
			details.addProperty(ALG_MEMBER, entry.getValue().alg);
			if (entry.getValue().jwk != null) {
				details.add(JWK_MEMBER, GSON.toJsonTree(entry.getValue().jwk));
			}
			for (Map.Entry<String, Object> vendorField : entry.getValue().vendorFields.entrySet()) {
				details.add(vendorField.getKey(), GSON.toJsonTree(vendorField.getValue()));
			}
			detailsObject.add(entry.getKey(), details);
		}
		root.add(Constants.RECIPIENT_DETAILS_FIELD, detailsObject);
		for (Map.Entry<String, JsonElement> entry : customFields.entrySet()) {
			root.add(entry.getKey(), entry.getValue());
		}
		return root.toString();
	}

	// base64url without padding, rejecting padding characters, foreign characters and non-zero trailing bits
	private static byte[] decodeStrict(String base64url) {
		byte[] bytes = B64_DECODER.decode(base64url);
		if (!B64.encodeToString(bytes).equals(base64url)) {
			throw new IllegalArgumentException("Non-canonical base64url");
		}
		return bytes;
	}

	static int decodeSeedId(String base64url) {
		byte[] bytes = decodeStrict(base64url);
		if (bytes.length != Constants.SEED_ID_LEN) {
			throw new IllegalArgumentException(String.format("seed id must be %s bytes", Constants.SEED_ID_LEN));
		}
		return ByteBuffer.wrap(bytes).getInt();
	}

	static String encodeSeedId(int seedId) {
		return B64.encodeToString(ByteBuffer.allocate(Constants.SEED_ID_LEN).putInt(seedId).array());
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
	 * @return The 32 byte digest of every seed by id, for seed pinning
	 */
	Map<Integer, byte[]> seedDigests() {
		assertNotDestroyed();
		Map<Integer, byte[]> result = new LinkedHashMap<>();
		for (Map.Entry<Integer, byte[]> entry : seeds.entrySet()) {
			result.put(entry.getKey(), seedDigest(kdfSalt, entry.getValue()));
		}
		return result;
	}

	/**
	 * @param digest A 32 byte seed digest
	 * @return Whether one of the seeds has this digest
	 */
	boolean hasSeedWithDigest(byte[] digest) {
		assertNotDestroyed();
		for (byte[] seed : seeds.values()) {
			byte[] candidate = seedDigest(kdfSalt, seed);
			boolean equal = Arrays.equals(candidate, digest);
			Arrays.fill(candidate, (byte) 0x00);
			if (equal) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @return The recipient details by kid (unmodifiable view)
	 */
	Map<String, RecipientDetails> recipientDetails() {
		return Collections.unmodifiableMap(recipientDetails);
	}

	void putRecipient(String kid, RecipientDetails details) {
		assertNotDestroyed();
		recipientDetails.put(kid, details);
	}

	void removeRecipient(String kid) {
		assertNotDestroyed();
		recipientDetails.remove(kid);
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
	 * Adds a fresh random seed and makes it the latest one. Its id is derived from the seed; a seed whose id collides with a different existing seed is redrawn.
	 *
	 * @param csprng Source of randomness
	 * @return The new seed's id
	 */
	int addSeed(SecureRandom csprng) {
		assertNotDestroyed();
		byte[] seed = new byte[Constants.SEED_LEN];
		int seedId;
		do {
			csprng.nextBytes(seed);
			seedId = seedId(kdfSalt, seed);
		} while (seeds.containsKey(seedId) && !Arrays.equals(seeds.get(seedId), seed));
		if (!seeds.containsKey(seedId)) {
			seeds.put(seedId, seed);
		}
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
