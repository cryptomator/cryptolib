package org.cryptomator.cryptolib.api;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;
import org.cryptomator.cryptolib.common.HKDFHelper;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * @see <a href="https://github.com/encryption-alliance/unified-vault-format/tree/develop/vault%20metadata#encrypted-content">UVF Vault Metadata Contents</a>
 */
public class UVFMasterkey implements RevolvingMasterkey {

	@VisibleForTesting final Map<Integer, byte[]> seeds;
	@VisibleForTesting final byte[] kdfSalt;
	@VisibleForTesting final int initialSeed;
	@VisibleForTesting final int latestSeed;

	public UVFMasterkey(Map<Integer, byte[]> seeds, byte[] kdfSalt, int initialSeed, int latestSeed) {
		this.seeds = new HashMap<>(seeds);
		this.kdfSalt = kdfSalt;
		this.initialSeed = initialSeed;
		this.latestSeed = latestSeed;
	}

	public static UVFMasterkey fromDecryptedPayload(String json) {
		JsonObject root = JsonParser.parseString(json).getAsJsonObject();
		Preconditions.checkArgument("AES-256-GCM-32k".equals(root.get("fileFormat").getAsString()));
		Preconditions.checkArgument("AES-SIV-512-B64URL".equals(root.get("nameFormat").getAsString()));
		Preconditions.checkArgument("HKDF-SHA512".equals(root.get("kdf").getAsString()));
		Preconditions.checkArgument(root.get("seeds").isJsonObject());

		Base64.Decoder base64 = Base64.getDecoder();
		byte[] initialSeed = base64.decode(root.get("initialSeed").getAsString());
		byte[] latestSeed = base64.decode(root.get("latestSeed").getAsString());
		byte[] kdfSalt = base64.decode(root.get("kdfSalt").getAsString());

		Map<Integer, byte[]> seeds = new HashMap<>();
		ByteBuffer intBuf = ByteBuffer.allocate(Integer.BYTES);
		for (Map.Entry<String, JsonElement> entry : root.getAsJsonObject("seeds").asMap().entrySet()) {
			intBuf.clear();
			intBuf.put(base64.decode(entry.getKey()));
			int seedNum = intBuf.getInt(0);
			byte[] seedVal = base64.decode(entry.getValue().getAsString());
			seeds.put(seedNum, seedVal);
		}
		return new UVFMasterkey(seeds, kdfSalt, ByteBuffer.wrap(initialSeed).getInt(), ByteBuffer.wrap(latestSeed).getInt());
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
			//Arrays.fill(subkey, (byte) 0x00);
		}
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
