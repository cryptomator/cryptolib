package org.cryptomator.cryptolib.internal.json;

import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.io.Writer;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * An immutable JSON value: exactly one of {@link Null}, {@link Bool}, {@link Num}, {@link Str}, {@link Arr} or {@link Obj}.
 * <p>
 * This is the only JSON API cryptolib's own code uses. Parsing and writing are delegated to a JSON library in a single place, so that the library can be exchanged there.
 *
 * @implNote The hierarchy is closed (private constructor, final nested subclasses) and can be declared {@code sealed} once the language level allows it. The nested names deliberately
 * avoid {@code String}, {@code Number}, {@code Boolean} and {@code Object}, which would shadow the {@code java.lang} types inside this class.
 */
public abstract class Json {

	private Json() {
	}

	/**
	 * Parses a JSON document leniently, i.e. accepting common deviations from the JSON grammar such as comments or single-quoted strings.
	 *
	 * @param json The document
	 * @return The document's value; {@link Null#INSTANCE} if the document is empty
	 * @throws ParseException If the document is malformed
	 */
	public static Json parse(String json) throws ParseException {
		try {
			return parse(new StringReader(json));
		} catch (IOException e) {
			throw new UncheckedIOException(e); // a StringReader does not fail
		}
	}

	/**
	 * Parses a JSON document leniently, see {@link #parse(String)}.
	 *
	 * @param reader Source of the document; not closed by this method
	 * @return The document's value; {@link Null#INSTANCE} if the document is empty
	 * @throws IOException If reading fails
	 * @throws ParseException If the document is malformed
	 */
	public static Json parse(Reader reader) throws IOException, ParseException {
		return GsonAdapter.read(reader);
	}

	/**
	 * Converts a plain Java object, the inverse of {@link #toJava()}.
	 *
	 * @param value {@code null}, a {@code Json}, {@code CharSequence}, {@code Boolean}, {@code Number}, {@code Map} with string keys or {@code Iterable}; the latter two containing such values
	 * @return The JSON value
	 * @throws IllegalArgumentException If the value or a nested value is of another type or a non-finite number
	 */
	public static Json of(@Nullable Object value) {
		if (value == null) {
			return Null.INSTANCE;
		} else if (value instanceof Json) {
			return (Json) value;
		} else if (value instanceof CharSequence) {
			return new Str(value.toString());
		} else if (value instanceof Boolean) {
			return Bool.valueOf((Boolean) value);
		} else if (value instanceof Number) {
			return new Num(value.toString());
		} else if (value instanceof Map) {
			return Obj.fromJava((Map<?, ?>) value);
		} else if (value instanceof Iterable) {
			return Arr.fromJava((Iterable<?>) value);
		} else {
			throw new IllegalArgumentException("Not representable in JSON: " + value.getClass().getName());
		}
	}

	/**
	 * Converts this value to plain Java objects, the inverse of {@link #of(Object)}.
	 *
	 * @return {@code null}, a {@code String}, {@code Boolean}, {@code Long} or {@code Double} (see {@link Num#toJava()}), unmodifiable {@code List} or unmodifiable {@code Map}
	 */
	public abstract @Nullable Object toJava();

	/**
	 * @return This value as compact JSON text
	 */
	public String serialize() {
		StringWriter writer = new StringWriter();
		try {
			write(writer, false);
		} catch (IOException e) {
			throw new UncheckedIOException(e); // a StringWriter does not fail
		}
		return writer.toString();
	}

	/**
	 * Writes this value as JSON text.
	 *
	 * @param writer Destination; flushed but not closed by this method
	 * @param pretty Whether to indent members and elements on separate lines
	 * @throws IOException If writing fails
	 */
	public void write(Writer writer, boolean pretty) throws IOException {
		GsonAdapter.write(this, writer, pretty);
	}

	@Override
	public String toString() {
		return serialize();
	}

	/**
	 * Thrown when a document is not JSON, not even leniently, or when a value in it is missing or not of the expected type.
	 */
	public static final class ParseException extends Exception {

		ParseException(String message) {
			super(message);
		}

		ParseException(String message, @Nullable Throwable cause) {
			super(message, cause);
		}

	}

	/**
	 * The JSON literal {@code null}.
	 */
	public static final class Null extends Json {

		// lives here and not in Json: a superclass initializer creating a subclass instance can deadlock class loading
		public static final Null INSTANCE = new Null();

		private Null() {
		}

		@Override
		public @Nullable Object toJava() {
			return null;
		}

	}

	/**
	 * One of the JSON literals {@code true} and {@code false}.
	 */
	public static final class Bool extends Json {

		private static final Bool TRUE = new Bool(true);
		private static final Bool FALSE = new Bool(false);

		private final boolean value;

		private Bool(boolean value) {
			this.value = value;
		}

		// not named "of": that would overload the inherited Json.of(Object), which wins for a boxed argument
		static Bool valueOf(boolean value) {
			return value ? TRUE : FALSE;
		}

		public boolean value() {
			return value;
		}

		@Override
		public Boolean toJava() {
			return value;
		}

	}

	/**
	 * A JSON number. It keeps the literal it was parsed from, so that writing it back does not alter its notation or precision.
	 */
	public static final class Num extends Json {

		private static final Pattern JSON_NUMBER = Pattern.compile("-?(?:0|[1-9]\\d*)(?:\\.\\d+)?(?:[eE][+-]?\\d+)?");

		private final String literal;
		private final BigDecimal value;

		Num(String literal) {
			if (!JSON_NUMBER.matcher(literal).matches()) {
				throw new IllegalArgumentException("Not a JSON number: " + literal);
			}
			this.literal = literal;
			this.value = new BigDecimal(literal);
		}

		/**
		 * @return The number as written in JSON text
		 */
		public String literal() {
			return literal;
		}

		/**
		 * @return The number's value, if it is an integer within the range of {@code int}
		 * @throws ArithmeticException If the number has a fractional part or is out of range
		 */
		public int intValueExact() {
			return value.intValueExact();
		}

		/**
		 * @return The number's value, if it is an integer within the range of {@code long}
		 * @throws ArithmeticException If the number has a fractional part or is out of range
		 */
		public long longValueExact() {
			return value.longValueExact();
		}

		public double doubleValue() {
			return value.doubleValue();
		}

		/**
		 * @return A {@code Long} if the number is written without fraction and exponent and fits; a {@code Double} otherwise
		 */
		@Override
		public Number toJava() {
			if (literal.indexOf('.') == -1 && literal.indexOf('e') == -1 && literal.indexOf('E') == -1) {
				try {
					return value.longValueExact();
				} catch (ArithmeticException e) {
					return value.doubleValue();
				}
			}
			return value.doubleValue();
		}

		@Override
		public boolean equals(@Nullable Object obj) {
			return obj instanceof Num && value.compareTo(((Num) obj).value) == 0; // numerically equal, regardless of notation
		}

		@Override
		public int hashCode() {
			return value.stripTrailingZeros().hashCode();
		}

	}

	/**
	 * A JSON string.
	 */
	public static final class Str extends Json {

		private final String value;

		Str(String value) {
			this.value = value;
		}

		public String value() {
			return value;
		}

		@Override
		public String toJava() {
			return value;
		}

		@Override
		public boolean equals(@Nullable Object obj) {
			return obj instanceof Str && value.equals(((Str) obj).value);
		}

		@Override
		public int hashCode() {
			return value.hashCode();
		}

	}

	/**
	 * A JSON array.
	 */
	public static final class Arr extends Json {

		private final List<Json> values;

		Arr(List<Json> values) {
			this.values = Collections.unmodifiableList(new ArrayList<>(values));
		}

		private static Arr fromJava(Iterable<?> javaValues) {
			List<Json> values = new ArrayList<>();
			for (Object javaValue : javaValues) {
				values.add(Json.of(javaValue));
			}
			return new Arr(values);
		}

		/**
		 * @return The array's elements (unmodifiable)
		 */
		public List<Json> values() {
			return values;
		}

		@Override
		public List<@Nullable Object> toJava() {
			List<@Nullable Object> result = new ArrayList<>(values.size());
			for (Json value : values) {
				result.add(value.toJava());
			}
			return Collections.unmodifiableList(result);
		}

		@Override
		public boolean equals(@Nullable Object obj) {
			return obj instanceof Arr && values.equals(((Arr) obj).values);
		}

		@Override
		public int hashCode() {
			return values.hashCode();
		}

	}

	/**
	 * A JSON object. Members keep their order; two objects are equal regardless of it.
	 */
	public static final class Obj extends Json {

		private final Map<String, Json> members;

		Obj(Map<String, Json> members) {
			this.members = Collections.unmodifiableMap(new LinkedHashMap<>(members));
		}

		private static Obj fromJava(Map<?, ?> javaMembers) {
			Map<String, Json> members = new LinkedHashMap<>();
			for (Map.Entry<?, ?> javaMember : javaMembers.entrySet()) {
				if (!(javaMember.getKey() instanceof String)) {
					throw new IllegalArgumentException("Not a JSON member name: " + javaMember.getKey());
				}
				members.put((String) javaMember.getKey(), Json.of(javaMember.getValue()));
			}
			return new Obj(members);
		}

		/**
		 * @param name A member name
		 * @return The member's value, which may be {@link Null#INSTANCE}; {@code null} if there is no such member
		 */
		public @Nullable Json get(String name) {
			return members.get(name);
		}

		/**
		 * @param name A member name
		 * @return The member's value
		 * @throws ParseException If there is no such member or it is not a string
		 */
		public String getString(String name) throws ParseException {
			Json value = members.get(name);
			if (!(value instanceof Str)) {
				throw invalidMember(name, null);
			}
			return ((Str) value).value();
		}

		/**
		 * @param name A member name
		 * @param defaultValue The result if there is no such member or it is {@link Null#INSTANCE}
		 * @return The member's value or the default
		 * @throws ParseException If the member is neither a string nor {@link Null#INSTANCE}
		 */
		public @Nullable String getString(String name, @Nullable String defaultValue) throws ParseException {
			return isAbsent(name) ? defaultValue : getString(name);
		}

		/**
		 * @param name A member name
		 * @return The member's value
		 * @throws ParseException If there is no such member or it is not an integer within the range of {@code int}
		 */
		public int getInt(String name) throws ParseException {
			Json value = members.get(name);
			if (!(value instanceof Num)) {
				throw invalidMember(name, null);
			}
			try {
				return ((Num) value).intValueExact();
			} catch (ArithmeticException e) {
				throw invalidMember(name, e);
			}
		}

		/**
		 * @param name A member name
		 * @param defaultValue The result if there is no such member or it is {@link Null#INSTANCE}
		 * @return The member's value or the default
		 * @throws ParseException If the member is neither an integer within the range of {@code int} nor {@link Null#INSTANCE}
		 */
		public int getInt(String name, int defaultValue) throws ParseException {
			return isAbsent(name) ? defaultValue : getInt(name);
		}

		/**
		 * @param name A member name
		 * @return The member's value
		 * @throws ParseException If there is no such member or it is not an object
		 */
		public Obj getObj(String name) throws ParseException {
			Json value = members.get(name);
			if (!(value instanceof Obj)) {
				throw invalidMember(name, null);
			}
			return (Obj) value;
		}

		private boolean isAbsent(String name) {
			Json value = members.get(name);
			return value == null || value == Null.INSTANCE;
		}

		private static ParseException invalidMember(String name, @Nullable Throwable cause) {
			return new ParseException("Missing or invalid member: " + name, cause);
		}

		/**
		 * @return The object's members in their order (unmodifiable)
		 */
		public Map<String, Json> members() {
			return members;
		}

		@Override
		public Map<String, @Nullable Object> toJava() {
			Map<String, @Nullable Object> result = new LinkedHashMap<>();
			for (Map.Entry<String, Json> member : members.entrySet()) {
				result.put(member.getKey(), member.getValue().toJava());
			}
			return Collections.unmodifiableMap(result);
		}

		@Override
		public boolean equals(@Nullable Object obj) {
			return obj instanceof Obj && members.equals(((Obj) obj).members);
		}

		@Override
		public int hashCode() {
			return members.hashCode();
		}

	}

}
