package org.cryptomator.cryptolib.common;

import com.google.common.io.BaseEncoding;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonIOException;
import com.google.gson.JsonParseException;
import com.google.gson.TypeAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;

/**
 * Representation of encrypted masterkey json file. Used by {@link MasterkeyFileAccess} to load and persist keys.
 */
public class MasterkeyFile {

	private static final Gson GSON = new GsonBuilder() //
			.setPrettyPrinting() //
			.disableHtmlEscaping() //
			.registerTypeHierarchyAdapter(byte[].class, new MasterkeyFile.ByteArrayJsonAdapter()) //
			.create();

	@SerializedName("version")
	public int version;

	@SerializedName("scryptSalt")
	public byte[] scryptSalt;

	@SerializedName("scryptCostParam")
	public int scryptCostParam;

	@SerializedName("scryptBlockSize")
	public int scryptBlockSize;

	@SerializedName("primaryMasterKey")
	public byte[] encMasterKey;

	@SerializedName("hmacMasterKey")
	public byte[] macMasterKey;

	@SerializedName("versionMac")
	public byte[] versionMac;

	public static MasterkeyFile read(Reader reader) throws IOException {
		try {
			MasterkeyFile result = GSON.fromJson(reader, MasterkeyFile.class);
			if (result == null) {
				throw new IOException("JSON EOF");
			} else {
				return result;
			}
		} catch (JsonParseException e) {
			throw new IOException("Unreadable JSON", e);
		} catch (IllegalArgumentException e) {
			throw new IOException("Invalid JSON content", e);
		}
	}

	public void write(Writer writer) throws IOException {
		try {
			GSON.toJson(this, writer);
		} catch (JsonIOException e) {
			throw new IOException(e);
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

	private static class ByteArrayJsonAdapter extends TypeAdapter<byte[]> {

		private static final BaseEncoding BASE64 = BaseEncoding.base64();

		@Override
		public void write(JsonWriter writer, byte[] value) throws IOException {
			if (value == null) {
				writer.nullValue();
			} else {
				writer.value(BASE64.encode(value));
			}
		}

		@Override
		public byte[] read(JsonReader reader) throws IOException {
			if (reader.peek() == JsonToken.NULL) {
				reader.nextNull();
				return null;
			} else {
				return BASE64.decode(reader.nextString());
			}
		}
	}

}
