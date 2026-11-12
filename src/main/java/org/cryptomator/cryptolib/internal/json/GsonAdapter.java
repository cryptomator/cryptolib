package org.cryptomator.cryptolib.internal.json;

import com.google.gson.Strictness;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;
import com.google.gson.stream.MalformedJsonException;

import java.io.EOFException;
import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Reads and writes {@link Json} values with Gson's streaming API. This is the only class that knows the JSON library.
 */
final class GsonAdapter {

	private GsonAdapter() {
	}

	// same behaviour as Gson's JsonParser: lenient, an empty document is null, nothing may follow the value
	static Json read(Reader reader) throws IOException, Json.ParseException {
		JsonReader in = new JsonReader(reader);
		in.setStrictness(Strictness.LENIENT);
		boolean empty = true;
		try {
			in.peek();
			empty = false;
			Json result = readValue(in);
			if (in.peek() != JsonToken.END_DOCUMENT) {
				throw new Json.ParseException("Did not consume the entire document");
			}
			return result;
		} catch (EOFException e) {
			if (empty) {
				return Json.Null.INSTANCE;
			}
			throw new Json.ParseException("Incomplete JSON", e);
		} catch (MalformedJsonException | IllegalStateException | IllegalArgumentException e) {
			throw new Json.ParseException("Malformed JSON", e);
		}
	}

	private static Json readValue(JsonReader in) throws IOException {
		switch (in.peek()) {
			case BEGIN_OBJECT:
				return readObject(in);
			case BEGIN_ARRAY:
				return readArray(in);
			case STRING:
				return new Json.Str(in.nextString());
			case NUMBER:
				return new Json.Num(in.nextString()); // the literal as written
			case BOOLEAN:
				return Json.Bool.valueOf(in.nextBoolean());
			case NULL:
				in.nextNull();
				return Json.Null.INSTANCE;
			default:
				throw new MalformedJsonException("Unexpected token " + in.peek());
		}
	}

	private static Json readObject(JsonReader in) throws IOException {
		Map<String, Json> members = new LinkedHashMap<>();
		in.beginObject();
		while (in.hasNext()) {
			members.put(in.nextName(), readValue(in)); // a repeated name keeps its position and takes the last value
		}
		in.endObject();
		return new Json.Obj(members);
	}

	private static Json readArray(JsonReader in) throws IOException {
		List<Json> values = new ArrayList<>();
		in.beginArray();
		while (in.hasNext()) {
			values.add(readValue(in));
		}
		in.endArray();
		return new Json.Arr(values);
	}

	static void write(Json json, Writer writer, boolean pretty) throws IOException {
		JsonWriter out = new JsonWriter(writer);
		out.setStrictness(Strictness.LENIENT);
		out.setHtmlSafe(false); // base64 padding stays "=" instead of "="
		out.setSerializeNulls(true);
		if (pretty) {
			out.setIndent("  ");
		}
		writeValue(json, out);
		out.flush();
	}

	private static void writeValue(Json json, JsonWriter out) throws IOException {
		if (json instanceof Json.Obj) {
			out.beginObject();
			for (Map.Entry<String, Json> member : ((Json.Obj) json).members().entrySet()) {
				out.name(member.getKey());
				writeValue(member.getValue(), out);
			}
			out.endObject();
		} else if (json instanceof Json.Arr) {
			out.beginArray();
			for (Json value : ((Json.Arr) json).values()) {
				writeValue(value, out);
			}
			out.endArray();
		} else if (json instanceof Json.Str) {
			out.value(((Json.Str) json).value());
		} else if (json instanceof Json.Num) {
			out.jsonValue(((Json.Num) json).literal());
		} else if (json instanceof Json.Bool) {
			out.value(((Json.Bool) json).value());
		} else {
			out.nullValue();
		}
	}

}
