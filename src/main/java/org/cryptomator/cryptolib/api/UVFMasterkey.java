package org.cryptomator.cryptolib.api;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;
import org.cryptomator.cryptolib.common.HKDFHelper;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * The decrypted payload of a UVF vault metadata file ({@code vault.uvf}): the seeds, the KDF salt and the initial and latest seed IDs.
 * <p>
 * This class covers the payload only. Decrypting and validating the surrounding JWE (protected header, recipients and {@code recipientDetails}),
 * writing an updated {@code vault.uvf} and persisting the {@link #seedDigests() seed digests} for seed pinning are the responsibility of the caller,
 * see the <a href="https://github.com/encryption-alliance/unified-vault-format/blob/develop/implementation-notes.md">UVF implementation notes</a>.
 *
 * @see <a href="https://github.com/encryption-alliance/unified-vault-format/tree/develop/vault%20metadata#encrypted-content">UVF Vault Metadata Contents</a>
 */
public class UVFMasterkey implements RevolvingMasterkey {

	private static final int SEED_LEN = 32;
	private static final int SEED_ID_LEN = 4;
	private static final int SEED_DIGEST_LEN = 32;
	private static final int KDF_SALT_LEN = 32;
	private static final byte[] ROOT_DIRID_KDF_CONTEXT = "rootDirId".getBytes(StandardCharsets.US_ASCII);
	private static final byte[] SEED_DIGEST_KDF_CONTEXT = "seedDigest".getBytes(StandardCharsets.US_ASCII);

	@VisibleForTesting final Map<Integer, byte[]> seeds;
	@VisibleForTesting final byte[] kdfSalt;
	@VisibleForTesting final int initialSeed;
	@VisibleForTesting final int latestSeed;

	/**
	 * Creates a masterkey from already validated components.
	 *
	 * @param seeds The seeds keyed by their {@link #seedId(byte[], byte[]) ID}
	 * @param kdfSalt The 32 byte KDF salt
	 * @param initialSeed The ID of the initial seed
	 * @param latestSeed The ID of the latest seed
	 * @throws IllegalArgumentException If a seed, the salt or an ID violates the specification
	 */
	public UVFMasterkey(Map<Integer, byte[]> seeds, byte[] kdfSalt, int initialSeed, int latestSeed) {
		Preconditions.checkArgument(kdfSalt.length == KDF_SALT_LEN, "kdfSalt must be %s bytes", KDF_SALT_LEN);
		Preconditions.checkArgument(!seeds.isEmpty(), "seeds must not be empty");
		for (Map.Entry<Integer, byte[]> entry : seeds.entrySet()) {
			Preconditions.checkArgument(entry.getValue().length == SEED_LEN, "seed must be %s bytes", SEED_LEN);
			Preconditions.checkArgument(seedId(kdfSalt, entry.getValue()) == entry.getKey(), "seed ID %s does not match its seed", entry.getKey());
		}
		Preconditions.checkArgument(seeds.containsKey(initialSeed), "initialSeed not found in seeds");
		Preconditions.checkArgument(seeds.containsKey(latestSeed), "latestSeed not found in seeds");
		this.seeds = new HashMap<>(); // defensive copies, as destroy() zeroes them
		for (Map.Entry<Integer, byte[]> entry : seeds.entrySet()) {
			this.seeds.put(entry.getKey(), entry.getValue().clone());
		}
		this.kdfSalt = kdfSalt.clone();
		this.initialSeed = initialSeed;
		this.latestSeed = latestSeed;
	}

	/**
	 * Parses and validates the decrypted JSON payload of a {@code vault.uvf} file.
	 *
	 * @param json The decrypted payload
	 * @return The masterkey
	 * @throws IllegalArgumentException If the payload is malformed, uses unsupported formats or violates the specification's validation rules
	 */
	public static UVFMasterkey fromDecryptedPayload(String json) {
		JsonObject root = JsonParser.parseString(json).getAsJsonObject();
		Preconditions.checkArgument("AES-256-GCM-32k".equals(root.get("fileFormat").getAsString()), "unsupported fileFormat");
		Preconditions.checkArgument("AES-SIV-512-B64URL".equals(root.get("nameFormat").getAsString()), "unsupported nameFormat");
		Preconditions.checkArgument("HKDF-SHA512".equals(root.get("kdf").getAsString()), "unsupported kdf");
		Preconditions.checkArgument(root.get("seeds").isJsonObject(), "seeds must be an object");

		byte[] kdfSalt = decodeBase64Url(root.get("kdfSalt").getAsString());
		int initialSeed = decodeSeedId(root.get("initialSeed").getAsString());
		int latestSeed = decodeSeedId(root.get("latestSeed").getAsString());

		Map<Integer, byte[]> seeds = new HashMap<>();
		for (Map.Entry<String, JsonElement> entry : root.getAsJsonObject("seeds").asMap().entrySet()) {
			int seedNum = decodeSeedId(entry.getKey());
			byte[] seedVal = decodeBase64Url(entry.getValue().getAsString());
			seeds.put(seedNum, seedVal);
		}
		return new UVFMasterkey(seeds, kdfSalt, initialSeed, latestSeed);
	}

	// decodes unpadded base64url and rejects padding, foreign characters and non-zero trailing bits
	private static byte[] decodeBase64Url(String str) {
		byte[] result = Base64.getUrlDecoder().decode(str);
		Preconditions.checkArgument(Base64.getUrlEncoder().withoutPadding().encodeToString(result).equals(str), "non-canonical base64url: %s", str);
		return result;
	}

	private static int decodeSeedId(String str) {
		byte[] bytes = decodeBase64Url(str);
		Preconditions.checkArgument(bytes.length == SEED_ID_LEN, "seed ID must be %s bytes: %s", SEED_ID_LEN, str);
		return ByteBuffer.wrap(bytes).getInt();
	}

	/**
	 * Computes the digest from which a seed's ID is derived.
	 *
	 * @param kdfSalt The vault's KDF salt
	 * @param seed The seed
	 * @return The 32 byte seed digest
	 * @see <a href="https://github.com/encryption-alliance/unified-vault-format/tree/develop/vault%20metadata#seed-ids">UVF Seed IDs</a>
	 */
	public static byte[] seedDigest(byte[] kdfSalt, byte[] seed) {
		return HKDFHelper.hkdfSha512(kdfSalt, seed, SEED_DIGEST_KDF_CONTEXT, SEED_DIGEST_LEN);
	}

	/**
	 * Derives the ID of a seed, i.e. the first four bytes of its {@link #seedDigest(byte[], byte[]) digest} as a big-endian integer.
	 *
	 * @param kdfSalt The vault's KDF salt
	 * @param seed The seed
	 * @return The seed ID
	 */
	public static int seedId(byte[] kdfSalt, byte[] seed) {
		byte[] digest = seedDigest(kdfSalt, seed);
		try {
			return ByteBuffer.wrap(digest).getInt();
		} finally {
			Arrays.fill(digest, (byte) 0x00);
		}
	}

	/**
	 * Returns the digests of all seeds, which a caller persists outside the vault to detect a rolled back or forged {@code vault.uvf} on subsequent unlocks.
	 *
	 * @return The 32 byte seed digest per seed ID
	 * @see <a href="https://github.com/encryption-alliance/unified-vault-format/blob/develop/implementation-notes.md#seed-pinning">UVF Seed Pinning</a>
	 */
	public Map<Integer, byte[]> seedDigests() {
		if (isDestroyed()) {
			throw new IllegalStateException("Masterkey is destroyed");
		}
		Map<Integer, byte[]> result = new HashMap<>();
		for (Map.Entry<Integer, byte[]> entry : seeds.entrySet()) {
			result.put(entry.getKey(), seedDigest(kdfSalt, entry.getValue()));
		}
		return Collections.unmodifiableMap(result);
	}

	@Override
	public int firstRevision() {
		return initialSeed;
	}

	@Override
	public int currentRevision() {
		return latestSeed;
	}

	@Override
	public byte[] rootDirId() {
		return HKDFHelper.hkdfSha512(kdfSalt, seeds.get(initialSeed), ROOT_DIRID_KDF_CONTEXT, 32);
	}

	@Override
	public DestroyableSecretKey subKey(int revision, int length, byte[] context, String algorithm) {
		if (isDestroyed()) {
			throw new IllegalStateException("Masterkey is destroyed");
		}
		if (!seeds.containsKey(revision)) {
			throw new IllegalArgumentException("No seed for revision " + revision);
		}
		byte[] subkey = HKDFHelper.hkdfSha512(kdfSalt, seeds.get(revision), context, length);
		try {
			return new DestroyableSecretKey(subkey, algorithm);
		} finally {
			Arrays.fill(subkey, (byte) 0x00);
		}
	}

	@Override
	public boolean isDestroyed() {
		return seeds.isEmpty(); // never empty before destroy()
	}

	@Override
	public void destroy() {
		Iterator<Map.Entry<Integer, byte[]>> iter = seeds.entrySet().iterator();
		while (iter.hasNext()) {
			Map.Entry<Integer, byte[]> entry = iter.next();
			Arrays.fill(entry.getValue(), (byte) 0x00);
			iter.remove();
		}
		Arrays.fill(kdfSalt, (byte) 0x00);
	}
}
