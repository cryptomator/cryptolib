package org.cryptomator.cryptolib.cvf8;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.NameShortener;
import org.cryptomator.cryptolib.api.ShortenedVaultNode;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

class Cvf8NameShortenerTest {

	// the 228 character example of the UVF shortening spec with a CVF8 extension; hash: printf '%s' "$LONG_NAME" | openssl dgst -sha1 -binary | base64 | tr '+/' '-_'
	private static final String LONG_NAME = "cAp6_KasM-0d74bYyP1eOpweCA4NGgwjVfDGc6heAlXbLIVq2tMWskWpw-DGgyoC63Tjjs3weXCL3hjGfQlP_uJDocVs7kxvIKDEsnHk2GYEnbLGJgCsYcIahvxW9PLxkIXowBkEcaedqWWZNmW0Cv0e9-EaPHmiveg-uvH7Hdp0vxEbxqxRioJBDN1jmVVfV-rE8fCa6ijyBJXYem0IvMLYl4wNgi0G.c9r";
	private static final String LONG_NAME_SHORTENED = "jiXgFOc_c1yEFhcXzEJ-Tngqw94=.c9s";

	private final NameShortener shortener = NameShortener.cvf8(220);

	@Test
	@DisplayName("layout of a shortened node")
	void testShorten() {
		Assertions.assertEquals(220, shortener.threshold());
		ShortenedVaultNode node = shortener.shorten(LONG_NAME);
		Assertions.assertNotNull(node);
		Assertions.assertEquals(LONG_NAME, node.name());
		Assertions.assertEquals(LONG_NAME_SHORTENED, node.shortenedName());
		Assertions.assertEquals(LONG_NAME_SHORTENED + "/contents.c9r", node.contentsFile());
		Assertions.assertEquals(LONG_NAME_SHORTENED + "/dir.c9r", node.dirFile());
		Assertions.assertEquals(LONG_NAME_SHORTENED + "/symlink.c9r", node.symlinkFile());
		Assertions.assertEquals(LONG_NAME_SHORTENED + "/name.c9s", node.sidecarFile());
		Assertions.assertArrayEquals(LONG_NAME.getBytes(UTF_8), node.sidecarContents());
		Assertions.assertEquals(node, shortener.shorten(LONG_NAME));
	}

	@Test
	@DisplayName("shortened name is base64url(sha1(name)) + .c9s, as in cryptofs")
	void testHashVector() {
		// printf 'foo.c9r' | openssl dgst -sha1 -binary | base64 | tr '+/' '-_'
		ShortenedVaultNode node = NameShortener.cvf8(6).shorten("foo.c9r");
		Assertions.assertNotNull(node);
		Assertions.assertEquals("XzXY10UamRa7Fdaj94oXgEWr_tM=.c9s", node.shortenedName());
	}

	@Test
	@DisplayName("names up to the threshold are not shortened")
	void testThreshold() {
		Assertions.assertNull(shortener.shorten(repeat('a', 216) + ".c9r"));
		Assertions.assertNotNull(shortener.shorten(repeat('a', 217) + ".c9r"));
		Assertions.assertNull(shortener.shorten("dirid.c9r"));
	}

	@Test
	@DisplayName("short names that look shortened are reserved")
	void testReservedNames() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> shortener.shorten(LONG_NAME_SHORTENED));
		Assertions.assertThrows(IllegalArgumentException.class, () -> shortener.shorten("foo.c9s"));
	}

	@ParameterizedTest(name = "{0} is not a shortened name")
	@ValueSource(strings = {"foo.c9r", "foo.c9s", "jiXgFOc_c1yEFhcXzEJ-Tngqw94= (1).c9s", "jiXgFOc_c1yEFhcXzEJ-Tngqw94=.c9r", "jiXgFOc_c1yEFhcXzEJ-Tngqw94.c9s", "jiXgFOc/c1yEFhcXzEJ+Tngqw94=.c9s", "name.c9s", ""})
	void testIsNotShortened(String entryName) {
		Assertions.assertFalse(shortener.isShortened(entryName));
		Assertions.assertFalse(shortener.isSidecar(entryName));
		Assertions.assertThrows(IllegalArgumentException.class, () -> shortener.sidecarFile(entryName));
		Assertions.assertThrows(IllegalArgumentException.class, () -> shortener.unshorten(entryName, LONG_NAME.getBytes(UTF_8)));
	}

	@Test
	@DisplayName("unshorten verifies the sidecar against the entry name")
	void testUnshorten() {
		Assertions.assertTrue(shortener.isShortened(LONG_NAME_SHORTENED));
		Assertions.assertFalse(shortener.isSidecar(LONG_NAME_SHORTENED));
		Assertions.assertEquals(LONG_NAME_SHORTENED + "/name.c9s", shortener.sidecarFile(LONG_NAME_SHORTENED));
		Assertions.assertEquals(LONG_NAME, shortener.unshorten(LONG_NAME_SHORTENED, LONG_NAME.getBytes(UTF_8)));

		String otherName = repeat('b', 300) + ".c9r";
		Assertions.assertThrows(AuthenticationFailedException.class, () -> shortener.unshorten(LONG_NAME_SHORTENED, otherName.getBytes(UTF_8)), "sidecar of another node");
		Assertions.assertThrows(AuthenticationFailedException.class, () -> shortener.unshorten(LONG_NAME_SHORTENED, new byte[0]));
		Assertions.assertThrows(AuthenticationFailedException.class, () -> shortener.unshorten(LONG_NAME_SHORTENED, (LONG_NAME + "\n").getBytes(UTF_8)));
	}

	@Test
	@DisplayName("a sidecar that hashes to the entry name but is not UTF-8 is rejected")
	void testUnshortenNonUtf8() throws NoSuchAlgorithmException {
		byte[] invalidUtf8 = new byte[300];
		Arrays.fill(invalidUtf8, (byte) 0xFF);
		String entryName = Base64.getUrlEncoder().encodeToString(MessageDigest.getInstance("SHA-1").digest(invalidUtf8)) + ".c9s";
		Assertions.assertTrue(shortener.isShortened(entryName));
		Assertions.assertThrows(AuthenticationFailedException.class, () -> shortener.unshorten(entryName, invalidUtf8));
	}

	private static String repeat(char c, int n) {
		char[] chars = new char[n];
		Arrays.fill(chars, c);
		return new String(chars);
	}

}
