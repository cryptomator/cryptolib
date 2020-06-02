/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.api;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.lang.reflect.Type;
import java.nio.charset.Charset;

import com.google.common.io.BaseEncoding;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import com.google.gson.stream.JsonReader;

/**
 * OOP-JSON interface for the masterkey file.<br>
 * <br>
 * Each version might have its own package-private subclass of this file, which adds further properties.
 * These properties must be annotated with {@link Expose} in order to be considered by {@link #serialize()}.
 */
public abstract class KeyFile {

	private static final Charset UTF_8 = Charset.forName("UTF-8");
	private static final Gson GSON = new GsonBuilder().setPrettyPrinting() //
			.registerTypeHierarchyAdapter(byte[].class, new ByteArrayJsonAdapter()) //
			.setLenient() //
			.disableHtmlEscaping() //
			.excludeFieldsWithoutExposeAnnotation().create();

	@Expose
	@SerializedName("version")
	private int version;

	private JsonObject jsonObj;

	/**
	 * @return Version (i.e. vault format) stored in the masterkey file.
	 * @see #setVersion(int)
	 */
	public int getVersion() {
		return version;
	}

	/**
	 * @param version The vault format used to distinguish different implementations needed to access encrypted contents.
	 */
	public void setVersion(int version) {
		this.version = version;
	}

	/**
	 * Parses a json keyfile.
	 * 
	 * @param serialized Json content.
	 * @return A new KeyFile instance.
	 */
	public static KeyFile parse(byte[] serialized) {
		try (InputStream in = new ByteArrayInputStream(serialized); //
				Reader reader = new InputStreamReader(in, UTF_8)) {
			JsonElement json = JsonParser.parseReader(reader);
			if (json.isJsonObject()) {
				KeyFile result = GSON.fromJson(json, GenericKeyFile.class);
				result.jsonObj = json.getAsJsonObject();
				return result;
			} else {
				throw new IllegalArgumentException("Key file doesn't contain json object.");
			}
		} catch (IOException | JsonParseException e) {
			throw new IllegalArgumentException("Unable to parse key file.", e);
		}
	}

	/**
	 * Creates a JSON representation of this instance.
	 * 
	 * @return UTF-8-encoded byte array of the JSON representation.
	 */
	public byte[] serialize() {
		return GSON.toJson(this).getBytes(UTF_8);
	}

	/**
	 * Creates a new version-specific KeyFile instance from this instance.
	 * 
	 * @param clazz Version-specific subclass of KeyFile.
	 * @param <T> Specific KeyFile implementation type.
	 * @return New instance of the given class.
	 */
	public <T extends KeyFile> T as(Class<T> clazz) {
		T result = GSON.fromJson(jsonObj, clazz);
		((KeyFile) result).jsonObj = jsonObj;
		return result;
	}

	private static class GenericKeyFile extends KeyFile {
	}

	private static class ByteArrayJsonAdapter implements JsonSerializer<byte[]>, JsonDeserializer<byte[]> {

		private static final BaseEncoding BASE64 = BaseEncoding.base64();

		@Override
		public byte[] deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
			return BASE64.decode(json.getAsString());
		}

		@Override
		public JsonElement serialize(byte[] src, Type typeOfSrc, JsonSerializationContext context) {
			return new JsonPrimitive(BASE64.encode(src));
		}

	}

}
