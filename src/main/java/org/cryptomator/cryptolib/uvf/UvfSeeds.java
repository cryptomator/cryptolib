package org.cryptomator.cryptolib.uvf;

import org.cryptomator.cryptolib.api.NameShortener;
import org.cryptomator.cryptolib.api.VaultConfigLoadException;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;
import org.cryptomator.cryptolib.common.HKDFHelper;
import org.cryptomator.cryptolib.internal.json.Json;
import org.jspecify.annotations.Nullable;

import javax.security.auth.Destroyable;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * The decrypted payload of {@code vault.uvf}: the vault's seeds, KDF salt, formats, name shortening threshold and recipient details, plus any fields cryptolib does not interpret.
 * <p>
 * Seed ids are derived from the seeds ({@code kdf(seed, 32, "seedDigest")[0..4]}) and verified on parsing.
 */
final class UvfSeeds implements Destroyable, AutoCloseable {

	private static final Base64.Encoder BASE64URL = Base64.getUrlEncoder().withoutPadding();
	private static final Base64.Decoder BASE64URL_DECODER = Base64.getUrlDecoder();
	private static final Set<String> KNOWN_FIELDS = new HashSet<>(Arrays.asList(Constants.FILE_FORMAT_FIELD, Constants.NAME_FORMAT_FIELD, Constants.SEEDS_FIELD, Constants.INITIAL_SEED_FIELD, Constants.LATEST_SEED_FIELD, Constants.KDF_FIELD, Constants.KDF_SALT_FIELD,
			Constants.NAME_SHORTENING_THRESHOLD_FIELD, Constants.RECIPIENT_DETAILS_FIELD));
	private static final String ALG_MEMBER = "alg";
	private static final String JWK_MEMBER = "jwk";

	/**
	 * One entry of the payload's {@code recipientDetails}: the recipient's key management algorithm, its public key for public-key algorithms, and vendor-specific members.
	 */
	static final class RecipientDetails {

		final String alg;
		final @Nullable Map<String, @Nullable Object> jwk;
		final Map<String, @Nullable Object> vendorFields;

		RecipientDetails(String alg, @Nullable Map<String, @Nullable Object> jwk, Map<String, @Nullable Object> vendorFields) {
			this.alg = alg;
			this.jwk = jwk == null ? null : Collections.unmodifiableMap(new LinkedHashMap<>(jwk));
			this.vendorFields = Collections.unmodifiableMap(new LinkedHashMap<>(vendorFields));
		}

	}

	private final Map<Integer, byte[]> seeds = new LinkedHashMap<>();
	private final byte[] kdfSalt;
	private final int initialSeedId;
	private int latestSeedId;
	private final int nameShorteningThreshold;
	private final Map<String, RecipientDetails> recipientDetails = new LinkedHashMap<>();
	private final Map<String, Json> customFields;
	private boolean destroyed = false;

	UvfSeeds(Map<Integer, byte[]> seeds, byte[] kdfSalt, int initialSeedId, int latestSeedId, int nameShorteningThreshold, Map<String, RecipientDetails> recipientDetails, Map<String, Json> customFields) {
		this.nameShorteningThreshold = UvfNameShortener.requireValidThreshold(nameShorteningThreshold);
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
	 * @param nameShorteningThreshold The vault's name shortening threshold, see {@link NameShortener#uvf(int)}
	 * @return Seeds for a new vault: a fresh salt and one seed, no recipients yet
	 * @throws IllegalArgumentException If the threshold is invalid
	 */
	static UvfSeeds create(SecureRandom csprng, int nameShorteningThreshold) {
		UvfNameShortener.requireValidThreshold(nameShorteningThreshold);
		byte[] kdfSalt = new byte[Constants.KDF_SALT_LEN];
		csprng.nextBytes(kdfSalt);
		byte[] seed = new byte[Constants.SEED_LEN];
		csprng.nextBytes(seed);
		try {
			int seedId = seedId(kdfSalt, seed);
			return new UvfSeeds(Collections.singletonMap(seedId, seed), kdfSalt, seedId, seedId, nameShorteningThreshold, Collections.emptyMap(), Collections.emptyMap());
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
			Json parsed = Json.parse(json);
			if (!(parsed instanceof Json.Obj)) {
				throw new VaultConfigLoadException("Vault metadata is not a JSON object");
			}
			Json.Obj root = (Json.Obj) parsed;
			requireFormat(root, Constants.FILE_FORMAT_FIELD, Constants.FILE_FORMAT);
			requireFormat(root, Constants.NAME_FORMAT_FIELD, Constants.NAME_FORMAT);
			requireFormat(root, Constants.KDF_FIELD, Constants.KDF);
			byte[] kdfSalt = decodeStrict(root.getString(Constants.KDF_SALT_FIELD));
			int initialSeed = decodeSeedId(root.getString(Constants.INITIAL_SEED_FIELD));
			int latestSeed = decodeSeedId(root.getString(Constants.LATEST_SEED_FIELD));
			Json.Obj seedsObject = root.getObj(Constants.SEEDS_FIELD);
			Map<Integer, byte[]> seeds = new LinkedHashMap<>();
			for (String seedId : seedsObject.members().keySet()) {
				seeds.put(decodeSeedId(seedId), decodeStrict(seedsObject.getString(seedId)));
			}
			// the optional field must be an integer; its range is checked by the constructor
			int nameShorteningThreshold = root.get(Constants.NAME_SHORTENING_THRESHOLD_FIELD) == null ? NameShortener.DISABLED : root.getInt(Constants.NAME_SHORTENING_THRESHOLD_FIELD);
			Map<String, RecipientDetails> recipientDetails = new LinkedHashMap<>();
			for (Map.Entry<String, Json> entry : root.getObj(Constants.RECIPIENT_DETAILS_FIELD).members().entrySet()) {
				recipientDetails.put(entry.getKey(), parseRecipientDetails(entry.getKey(), entry.getValue()));
			}
			Map<String, Json> customFields = new LinkedHashMap<>();
			for (Map.Entry<String, Json> entry : root.members().entrySet()) {
				if (!KNOWN_FIELDS.contains(entry.getKey())) {
					customFields.put(entry.getKey(), entry.getValue());
				}
			}
			return new UvfSeeds(seeds, kdfSalt, initialSeed, latestSeed, nameShorteningThreshold, recipientDetails, customFields);
		} catch (Json.ParseException e) {
			throw new VaultConfigLoadException("Malformed vault metadata: " + e.getMessage(), e);
		} catch (IllegalArgumentException e) {
			throw new VaultConfigLoadException("Malformed vault metadata", e);
		}
	}

	private static RecipientDetails parseRecipientDetails(String kid, Json json) throws VaultConfigLoadException, Json.ParseException {
		if (!(json instanceof Json.Obj)) {
			throw new VaultConfigLoadException("Invalid recipient details for " + kid);
		}
		Json.Obj object = (Json.Obj) json;
		String alg = object.getString(ALG_MEMBER);
		Map<String, @Nullable Object> jwk = null;
		Json jwkJson = object.get(JWK_MEMBER);
		if (jwkJson instanceof Json.Obj) {
			jwk = ((Json.Obj) jwkJson).toJava();
		} else if (jwkJson != null) {
			throw new VaultConfigLoadException("Invalid jwk in recipient details for " + kid);
		}
		Map<String, @Nullable Object> vendorFields = new LinkedHashMap<>();
		for (Map.Entry<String, Json> member : object.members().entrySet()) {
			if (!ALG_MEMBER.equals(member.getKey()) && !JWK_MEMBER.equals(member.getKey())) {
				vendorFields.put(member.getKey(), member.getValue().toJava());
			}
		}
		return new RecipientDetails(alg, jwk, vendorFields);
	}

	private static void requireFormat(Json.Obj root, String field, String expected) throws VaultConfigLoadException, Json.ParseException {
		String actual = root.getString(field);
		if (!expected.equals(actual)) {
			throw new VaultConfigLoadException("Unsupported " + field + ": " + actual);
		}
	}

	/**
	 * @return The JSON payload to encrypt into {@code vault.uvf}
	 */
	String toDecryptedPayload() {
		assertNotDestroyed();
		Map<String, Object> root = new LinkedHashMap<>();
		root.put(Constants.FILE_FORMAT_FIELD, Constants.FILE_FORMAT);
		root.put(Constants.NAME_FORMAT_FIELD, Constants.NAME_FORMAT);
		Map<String, Object> seedsObject = new LinkedHashMap<>();
		for (Map.Entry<Integer, byte[]> entry : seeds.entrySet()) {
			seedsObject.put(encodeSeedId(entry.getKey()), BASE64URL.encodeToString(entry.getValue()));
		}
		root.put(Constants.SEEDS_FIELD, seedsObject);
		root.put(Constants.INITIAL_SEED_FIELD, encodeSeedId(initialSeedId));
		root.put(Constants.LATEST_SEED_FIELD, encodeSeedId(latestSeedId));
		root.put(Constants.KDF_FIELD, Constants.KDF);
		root.put(Constants.KDF_SALT_FIELD, BASE64URL.encodeToString(kdfSalt));
		if (nameShorteningThreshold != NameShortener.DISABLED) {
			root.put(Constants.NAME_SHORTENING_THRESHOLD_FIELD, nameShorteningThreshold);
		}
		Map<String, Object> detailsObject = new LinkedHashMap<>();
		for (Map.Entry<String, RecipientDetails> entry : recipientDetails.entrySet()) {
			Map<String, @Nullable Object> details = new LinkedHashMap<>();
			details.put(ALG_MEMBER, entry.getValue().alg);
			if (entry.getValue().jwk != null) {
				details.put(JWK_MEMBER, entry.getValue().jwk);
			}
			details.putAll(entry.getValue().vendorFields);
			detailsObject.put(entry.getKey(), details);
		}
		root.put(Constants.RECIPIENT_DETAILS_FIELD, detailsObject);
		root.putAll(customFields);
		return Json.of(root).serialize();
	}

	// base64url without padding, rejecting padding characters, foreign characters and non-zero trailing bits
	private static byte[] decodeStrict(String base64url) {
		byte[] bytes = BASE64URL_DECODER.decode(base64url);
		if (!BASE64URL.encodeToString(bytes).equals(base64url)) {
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
		return BASE64URL.encodeToString(ByteBuffer.allocate(Constants.SEED_ID_LEN).putInt(seedId).array());
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

	/**
	 * @return The name shortening threshold, or {@link NameShortener#DISABLED}
	 */
	int nameShorteningThreshold() {
		return nameShorteningThreshold;
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
		for (Map.Entry<String, Json> entry : customFields.entrySet()) {
			result.put(entry.getKey(), entry.getValue().toJava());
		}
		return Collections.unmodifiableMap(result);
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
