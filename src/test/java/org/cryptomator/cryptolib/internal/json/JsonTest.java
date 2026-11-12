package org.cryptomator.cryptolib.internal.json;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.io.StringWriter;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

class JsonTest {

	@Test
	@DisplayName("every JSON type is parsed into its node type")
	void testParse() throws Json.ParseException {
		Json parsed = Json.parse("{\"s\":\"text\",\"n\":42,\"t\":true,\"f\":false,\"z\":null,\"a\":[1,\"two\",[]],\"o\":{\"x\":{}}}");
		Json.Obj obj = Assertions.assertInstanceOf(Json.Obj.class, parsed);
		Map<String, Json> members = obj.members();
		Assertions.assertEquals(Arrays.asList("s", "n", "t", "f", "z", "a", "o"), new ArrayList<>(members.keySet()), "members keep their order");
		Assertions.assertEquals("text", Assertions.assertInstanceOf(Json.Str.class, obj.get("s")).value());
		Assertions.assertEquals(42, Assertions.assertInstanceOf(Json.Num.class, obj.get("n")).intValueExact());
		Assertions.assertTrue(Assertions.assertInstanceOf(Json.Bool.class, obj.get("t")).value());
		Assertions.assertFalse(Assertions.assertInstanceOf(Json.Bool.class, obj.get("f")).value());
		Assertions.assertSame(Json.Null.INSTANCE, obj.get("z"), "a null member is present");
		Assertions.assertNull(obj.get("missing"));
		Json.Arr arr = Assertions.assertInstanceOf(Json.Arr.class, obj.get("a"));
		Assertions.assertEquals(3, arr.values().size());
		Assertions.assertInstanceOf(Json.Arr.class, arr.values().get(2));
		Assertions.assertInstanceOf(Json.Obj.class, Assertions.assertInstanceOf(Json.Obj.class, obj.get("o")).get("x"));
		Assertions.assertThrows(UnsupportedOperationException.class, members::clear);
		List<Json> values = arr.values();
		Assertions.assertThrows(UnsupportedOperationException.class, values::clear);
	}

	@Test
	@DisplayName("typed getters return a member of the expected type and fail otherwise")
	void testTypedGetters() throws Json.ParseException {
		Json.Obj obj = (Json.Obj) Json.parse("{\"s\":\"text\",\"i\":42,\"f\":42.0,\"d\":1.5,\"big\":4294967296,\"z\":null,\"o\":{\"x\":1}}");
		Assertions.assertEquals("text", obj.getString("s"));
		Assertions.assertEquals(42, obj.getInt("i"));
		Assertions.assertEquals(42, obj.getInt("f"), "an integer written with a fraction");
		Assertions.assertEquals(Json.parse("{\"x\":1}"), obj.getObj("o"));
		for (String name : new String[]{"i", "z", "o", "missing"}) {
			Assertions.assertThrows(Json.ParseException.class, () -> obj.getString(name));
		}
		for (String name : new String[]{"s", "d", "big", "z", "o", "missing"}) {
			Assertions.assertThrows(Json.ParseException.class, () -> obj.getInt(name));
		}
		for (String name : new String[]{"s", "i", "z", "missing"}) {
			Assertions.assertThrows(Json.ParseException.class, () -> obj.getObj(name));
		}
	}

	@Test
	@DisplayName("typed getters with a default treat a missing and a null member alike")
	void testTypedGettersWithDefault() throws Json.ParseException {
		Json.Obj obj = (Json.Obj) Json.parse("{\"s\":\"text\",\"i\":42,\"z\":null}");
		Assertions.assertEquals("text", obj.getString("s", "default"));
		Assertions.assertEquals("default", obj.getString("z", "default"));
		Assertions.assertEquals("default", obj.getString("missing", "default"));
		Assertions.assertNull(obj.getString("missing", null));
		Assertions.assertThrows(Json.ParseException.class, () -> obj.getString("i", "default"));
		Assertions.assertEquals(42, obj.getInt("i", -1));
		Assertions.assertEquals(-1, obj.getInt("z", -1));
		Assertions.assertEquals(-1, obj.getInt("missing", -1));
		Assertions.assertThrows(Json.ParseException.class, () -> obj.getInt("s", -1));
	}

	@Test
	@DisplayName("top-level values, an empty document and repeated member names")
	void testParseSpecialDocuments() throws Json.ParseException {
		Assertions.assertEquals(Json.of("text"), Json.parse("\"text\""));
		Assertions.assertEquals(Json.of(1), Json.parse(" 1 "));
		Assertions.assertSame(Json.Null.INSTANCE, Json.parse("null"));
		Assertions.assertSame(Json.Null.INSTANCE, Json.parse(""), "as Gson's JsonParser");
		Assertions.assertEquals(Json.parse("{\"a\":2,\"b\":1}"), Json.parse("{\"a\":1,\"b\":1,\"a\":2}"), "the last value wins");
	}

	@Test
	@DisplayName("parsing is lenient")
	void testParseLenient() throws Json.ParseException {
		Json expected = Json.parse("{\"a\":\"b\",\"c\":[1,2]}");
		Assertions.assertEquals(expected, Json.parse("{'a':'b', c:[1,2]} // comment"));
		Assertions.assertEquals(expected, Json.parse("/* comment */ {a:'b';c=[1;2]}"));
	}

	@ParameterizedTest(name = "{0} is malformed")
	@ValueSource(strings = {"{", "{\"a\":}", "[1,2", "\"unterminated", "{\"a\":1} trailing", "{\"a\":1}{\"b\":2}", "[1e99999999999]"})
	void testParseMalformed(String json) {
		Assertions.assertThrows(Json.ParseException.class, () -> Json.parse(json));
	}

	@ParameterizedTest(name = "{0} is written back unchanged")
	@ValueSource(strings = {"0", "-0", "42", "1.0", "1.50", "1e3", "1E+3", "-2.5e-7", "12345678901234567890", "0.1000000000000000055511151231257827"})
	void testNumberLiterals(String literal) throws Json.ParseException {
		Json.Num num = Assertions.assertInstanceOf(Json.Num.class, Json.parse(literal));
		Assertions.assertEquals(literal, num.literal());
		Assertions.assertEquals("[" + literal + "]", Json.parse("[" + literal + "]").serialize());
	}

	@Test
	@DisplayName("numbers compare by value and convert exactly or not at all")
	void testNumbers() throws Json.ParseException {
		Assertions.assertEquals(Json.parse("1000"), Json.parse("1e3"));
		Assertions.assertEquals(Json.parse("1000").hashCode(), Json.parse("1.0E3").hashCode());
		Assertions.assertNotEquals(Json.parse("1000"), Json.parse("1000.5"));
		Assertions.assertNotEquals(Json.parse("1"), Json.parse("\"1\""));

		Json.Num integral = (Json.Num) Json.parse("220.0");
		Assertions.assertEquals(220, integral.intValueExact());
		Assertions.assertEquals(220L, integral.longValueExact());
		Assertions.assertEquals(220.0, integral.doubleValue());
		Json.Num fractional = (Json.Num) Json.parse("220.5");
		Assertions.assertThrows(ArithmeticException.class, fractional::intValueExact);
		Assertions.assertThrows(ArithmeticException.class, fractional::longValueExact);
		Json.Num large = (Json.Num) Json.parse("4294967516");
		Assertions.assertThrows(ArithmeticException.class, large::intValueExact);
		Assertions.assertEquals(4294967516L, large.longValueExact());
		Json.Num huge = (Json.Num) Json.parse("1e999999999");
		Assertions.assertThrows(ArithmeticException.class, huge::longValueExact);
	}

	@Test
	@DisplayName("toJava yields plain Java objects")
	void testToJava() throws Json.ParseException {
		Object java = Json.parse("{\"s\":\"text\",\"i\":42,\"d\":1.0,\"e\":1e3,\"big\":12345678901234567890,\"t\":true,\"z\":null,\"a\":[1,null],\"o\":{\"x\":1}}").toJava();
		Map<?, ?> map = Assertions.assertInstanceOf(Map.class, java);
		Assertions.assertEquals("text", map.get("s"));
		Assertions.assertEquals(42L, map.get("i"));
		Assertions.assertEquals(1.0, map.get("d"), "written with a fraction");
		Assertions.assertEquals(1000.0, map.get("e"), "written with an exponent");
		Assertions.assertEquals(1.2345678901234567E19, map.get("big"), "integer beyond the range of long");
		Assertions.assertEquals(true, map.get("t"));
		Assertions.assertTrue(map.containsKey("z"));
		Assertions.assertNull(map.get("z"));
		Assertions.assertEquals(Arrays.asList(1L, null), map.get("a"));
		Assertions.assertEquals(Collections.singletonMap("x", 1L), map.get("o"));
		Assertions.assertThrows(UnsupportedOperationException.class, map::clear);
		Assertions.assertNull(Json.Null.INSTANCE.toJava());
	}

	@Test
	@DisplayName("of converts plain Java objects and is the inverse of toJava")
	void testOf() throws Json.ParseException {
		Map<String, Object> map = new LinkedHashMap<>();
		map.put("s", new StringBuilder("text"));
		map.put("i", 42);
		map.put("l", 42L);
		map.put("d", 1.5);
		map.put("bi", new BigInteger("12345678901234567890"));
		map.put("bd", new BigDecimal("1000").stripTrailingZeros());
		map.put("t", true);
		map.put("z", null);
		map.put("a", Arrays.asList(1, null, Collections.emptyList()));
		map.put("o", Collections.singletonMap("x", Json.of("y")));
		Json json = Json.of(map);
		Assertions.assertEquals("{\"s\":\"text\",\"i\":42,\"l\":42,\"d\":1.5,\"bi\":12345678901234567890,\"bd\":1E+3,\"t\":true,\"z\":null,\"a\":[1,null,[]],\"o\":{\"x\":\"y\"}}", json.serialize());
		Assertions.assertSame(json, Json.of(json));
		Assertions.assertSame(Json.Null.INSTANCE, Json.of(null));

		Json parsed = Json.parse("{\"s\":\"text\",\"i\":42,\"d\":1.0,\"t\":false,\"z\":null,\"a\":[1,null],\"o\":{\"x\":{\"y\":null}}}");
		Assertions.assertEquals(parsed, Json.of(parsed.toJava()));
		Assertions.assertEquals(parsed.serialize(), Json.of(parsed.toJava()).serialize());
	}

	@Test
	@DisplayName("of rejects what JSON cannot represent")
	void testOfUnsupported() {
		Date date = new Date(0);
		Assertions.assertThrows(IllegalArgumentException.class, () -> Json.of(date));
		Assertions.assertThrows(IllegalArgumentException.class, () -> Json.of(Double.NaN));
		Assertions.assertThrows(IllegalArgumentException.class, () -> Json.of(Double.POSITIVE_INFINITY));
		Map<Integer, String> intKeys = Collections.singletonMap(1, "x");
		Assertions.assertThrows(IllegalArgumentException.class, () -> Json.of(intKeys));
		List<Object> nested = Collections.singletonList(date);
		Assertions.assertThrows(IllegalArgumentException.class, () -> Json.of(nested));
	}

	@ParameterizedTest(name = "{0} is serialized compactly and without HTML escaping")
	@ValueSource(strings = {"\"a=b<c>&'\\\"\\\\\\n\\u0000\"", "[]", "{}", "{\"b\":1,\"a\":[true,false,null]}"})
	void testSerialize(String json) throws Json.ParseException {
		Json parsed = Json.parse(json);
		Assertions.assertEquals(json, parsed.serialize());
		Assertions.assertEquals(json, parsed.toString());
	}

	@Test
	@DisplayName("pretty output puts members and elements on separate lines, indented by two spaces")
	void testWritePretty() throws IOException, Json.ParseException {
		Json json = Json.parse("{\"a\":\"Zm9v\",\"b\":[1,2],\"c\":{}}");
		StringWriter writer = new StringWriter();
		json.write(writer, true);
		Assertions.assertEquals("{\n  \"a\": \"Zm9v\",\n  \"b\": [\n    1,\n    2\n  ],\n  \"c\": {}\n}", writer.toString());
		Assertions.assertEquals(json, Json.parse(writer.toString()));
	}

	@Test
	@DisplayName("values are equal regardless of member order, but not of element order")
	void testEquals() throws Json.ParseException {
		Assertions.assertEquals(Json.parse("{\"a\":1,\"b\":[1,2]}"), Json.parse("{\"b\":[1,2],\"a\":1}"));
		Assertions.assertEquals(Json.parse("{\"a\":1,\"b\":[1,2]}").hashCode(), Json.parse("{\"b\":[1,2],\"a\":1}").hashCode());
		Assertions.assertNotEquals(Json.parse("[1,2]"), Json.parse("[2,1]"));
		Assertions.assertNotEquals(Json.parse("{\"a\":null}"), Json.parse("{}"));
		Assertions.assertEquals(Json.parse("true"), Json.of(true));
		Assertions.assertNotEquals(Json.parse("true"), Json.parse("false"));
		Assertions.assertNotEquals(Json.parse("\"a\""), Json.parse("\"b\""));
	}

}
