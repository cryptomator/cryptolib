package org.cryptomator.cryptolib.common;

import org.cryptomator.cryptolib.internal.json.Json;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Representation of encrypted masterkey json file. Used by {@link MasterkeyFileAccess} to load and persist keys.
 */
public class MasterkeyFile {

	private static final Base64.Encoder BASE64 = Base64.getEncoder();
	private static final Base64.Decoder BASE64_DECODER = Base64.getDecoder();
	private static final class JsonKey {
		private static final String VERSION = "version";
		private static final String SCRYPT_SALT = "scryptSalt";
		private static final String SCRYPT_COST_PARAM = "scryptCostParam";
		private static final String SCRYPT_BLOCK_SIZE = "scryptBlockSize";
		private static final String ENC_MASTER_KEY = "primaryMasterKey";
		private static final String MAC_MASTER_KEY = "hmacMasterKey";
		private static final String VERSION_MAC = "versionMac";
	}

	public int version;
	public byte[] scryptSalt;
	public int scryptCostParam;
	public int scryptBlockSize;
	public byte[] encMasterKey;
	public byte[] macMasterKey;
	public byte[] versionMac;

	public static MasterkeyFile read(Reader reader) throws IOException {
		try {
			Json json = Json.parse(reader);
			if (json == Json.Null.INSTANCE) {
				throw new IOException("JSON EOF");
			} else if (!(json instanceof Json.Obj)) {
				throw new IOException("Unreadable JSON");
			}
			Json.Obj object = (Json.Obj) json;
			MasterkeyFile result = new MasterkeyFile();
			result.version = object.getInt(JsonKey.VERSION, 0);
			result.scryptSalt = base64Decode(object.getString(JsonKey.SCRYPT_SALT, null));
			result.scryptCostParam = object.getInt(JsonKey.SCRYPT_COST_PARAM, 0);
			result.scryptBlockSize = object.getInt(JsonKey.SCRYPT_BLOCK_SIZE, 0);
			result.encMasterKey = base64Decode(object.getString(JsonKey.ENC_MASTER_KEY, null));
			result.macMasterKey = base64Decode(object.getString(JsonKey.MAC_MASTER_KEY, null));
			result.versionMac = base64Decode(object.getString(JsonKey.VERSION_MAC, null));
			return result;
		} catch (Json.ParseException e) {
			throw new IOException("Unreadable JSON", e);
		} catch (IllegalArgumentException e) {
			throw new IOException("Invalid JSON content", e);
		}
	}

	private static byte @Nullable [] base64Decode(@Nullable String base64) {
		return base64 == null ? null : BASE64_DECODER.decode(base64);
	}

	public void write(Writer writer) throws IOException {
		Map<String, Object> members = new LinkedHashMap<>();
		members.put(JsonKey.VERSION, version);
		putBytes(members, JsonKey.SCRYPT_SALT, scryptSalt);
		members.put(JsonKey.SCRYPT_COST_PARAM, scryptCostParam);
		members.put(JsonKey.SCRYPT_BLOCK_SIZE, scryptBlockSize);
		putBytes(members, JsonKey.ENC_MASTER_KEY, encMasterKey);
		putBytes(members, JsonKey.MAC_MASTER_KEY, macMasterKey);
		putBytes(members, JsonKey.VERSION_MAC, versionMac);
		Json.of(members).write(writer, true);
	}

	// unset fields are omitted
	private static void putBytes(Map<String, Object> members, String name, byte[] value) {
		if (value != null) {
			members.put(name, BASE64.encodeToString(value));
		}
	}

	boolean isValid() {
		return version != 0
				&& scryptSalt != null
				&& scryptCostParam > 1
				&& scryptBlockSize > 0
				&& encMasterKey != null
				&& macMasterKey != null
				&& versionMac != null;
	}

}
