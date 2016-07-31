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
import java.io.InputStreamReader;
import java.io.Reader;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;

import org.apache.commons.codec.binary.Base64;

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

/**
 * OOP-JSON interface for the masterkey file.<br>
 * <br>
 * Each version might have its own package-private subclass of this file, which adds further properties.
 * These properties must be annotated with {@link Expose} in order to be considered by {@link #serialize()}.
 */
public abstract class KeyFile {

	private static final Gson GSON = new GsonBuilder().setPrettyPrinting() //
			.registerTypeHierarchyAdapter(byte[].class, new ByteArrayJsonAdapter()) //
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
		try {
			Reader reader = new InputStreamReader(new ByteArrayInputStream(serialized), StandardCharsets.UTF_8);
			JsonObject jsonObj = new JsonParser().parse(reader).getAsJsonObject();
			KeyFile result = GSON.fromJson(jsonObj, GenericKeyFile.class);
			result.jsonObj = jsonObj;
			return result;
		} catch (JsonParseException e) {
			throw new IllegalArgumentException("Unable to parse key file.", e);
		}
	}

	/**
	 * Creates a JSON representation of this instance.
	 * 
	 * @return UTF-8-encoded byte array of the JSON representation.
	 */
	public byte[] serialize() {
		return GSON.toJson(this).getBytes(StandardCharsets.UTF_8);
	}

	/**
	 * Creates a new version-specific KeyFile instance from this instance.
	 * 
	 * @param clazz Version-specific subclass of KeyFile.
	 * @return New instance of the given class.
	 */
	public <T extends KeyFile> T as(Class<T> clazz) {
		try {
			T result = GSON.fromJson(jsonObj, clazz);
			((KeyFile) result).jsonObj = jsonObj;
			return result;
		} catch (JsonParseException e) {
			throw new IllegalArgumentException("Unable to parse key file.", e);
		}
	}

	private static class GenericKeyFile extends KeyFile {
	}

	private static class ByteArrayJsonAdapter implements JsonSerializer<byte[]>, JsonDeserializer<byte[]> {

		@Override
		public byte[] deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
			return Base64.decodeBase64(json.getAsString());
		}

		@Override
		public JsonElement serialize(byte[] src, Type typeOfSrc, JsonSerializationContext context) {
			return new JsonPrimitive(Base64.encodeBase64String(src));
		}

	}

}
