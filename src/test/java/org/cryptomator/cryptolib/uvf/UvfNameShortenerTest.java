package org.cryptomator.cryptolib.uvf;

import org.bouncycastle.util.encoders.Base32;
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

import static java.nio.charset.StandardCharsets.UTF_8;

class UvfNameShortenerTest {

	// example from the UVF file name shortening specification: a 228 byte ciphertext name and its truncated SHA-256 in Base32
	private static final String SPEC_NAME = "cAp6_KasM-0d74bYyP1eOpweCA4NGgwjVfDGc6heAlXbLIVq2tMWskWpw-DGgyoC63Tjjs3weXCL3hjGfQlP_uJDocVs7kxvIKDEsnHk2GYEnbLGJgCsYcIahvxW9PLxkIXowBkEcaedqWWZNmW0Cv0e9-EaPHmiveg-uvH7Hdp0vxEbxqxRioJBDN1jmVVfV-rE8fCa6ijyBJXYem0IvMLYl4wNgi0G.uvf";
	private static final String SPEC_HASH = "WQ6QCEQX5BTXEPNQZNJLHDN52MADIVA4";
	private static final String SPEC_SHORTENED = SPEC_HASH + ".shortened.uvf";
	private static final String SPEC_SIDECAR = SPEC_HASH + ".original.uvf";

	private final NameShortener shortener = NameShortener.uvf(220);

	@Test
	@DisplayName("layout of a shortened node (spec example)")
	void testShorten() {
		Assertions.assertEquals(220, shortener.threshold());
		Assertions.assertEquals(228, SPEC_NAME.getBytes(UTF_8).length);
		ShortenedVaultNode node = shortener.shorten(SPEC_NAME);
		Assertions.assertNotNull(node);
		Assertions.assertEquals(SPEC_NAME, node.name());
		Assertions.assertEquals(SPEC_SHORTENED, node.shortenedName());
		Assertions.assertEquals(SPEC_SHORTENED, node.contentsFile(), "a file stays a file");
		Assertions.assertEquals(SPEC_SHORTENED + "/dir.uvf", node.dirFile());
		Assertions.assertEquals(SPEC_SHORTENED + "/symlink.uvf", node.symlinkFile());
		Assertions.assertEquals(SPEC_SIDECAR, node.sidecarFile());
		Assertions.assertArrayEquals(SPEC_NAME.getBytes(UTF_8), node.sidecarContents());
		Assertions.assertEquals(node, shortener.shorten(SPEC_NAME));
		Assertions.assertEquals(NameShortener.MIN_UVF_THRESHOLD, SPEC_SHORTENED.length(), "the minimum threshold is the length of a shortened name");
	}

	@Test
	@DisplayName("the threshold counts UTF-8 bytes; names up to it are not shortened")
	void testThreshold() {
		Assertions.assertNull(shortener.shorten(repeat('a', 216) + ".uvf"));
		Assertions.assertNotNull(shortener.shorten(repeat('a', 217) + ".uvf"));
		Assertions.assertNull(shortener.shorten(repeat('ä', 108) + ".uvf"), "112 chars, 220 bytes");
		Assertions.assertNotNull(shortener.shorten(repeat('ä', 109) + ".uvf"), "113 chars, 222 bytes");
		Assertions.assertNull(shortener.shorten("dir.uvf"));
		Assertions.assertNull(shortener.shorten("shortened.uvf"));
	}

	@ParameterizedTest(name = "{0} is reserved")
	@ValueSource(strings = {"WQ6QCEQX5BTXEPNQZNJLHDN52MADIVA4.shortened.uvf", "WQ6QCEQX5BTXEPNQZNJLHDN52MADIVA4.original.uvf", "foo.shortened.uvf", "foo.original (1).uvf", "foo.shortened (conflicted copy).uvf"})
	void testReservedNames(String name) {
		Assertions.assertThrows(IllegalArgumentException.class, () -> shortener.shorten(name));
	}

	@Test
	@DisplayName("classification of listed entries")
	void testClassification() {
		Assertions.assertTrue(shortener.isShortened(SPEC_SHORTENED));
		Assertions.assertFalse(shortener.isSidecar(SPEC_SHORTENED));
		Assertions.assertTrue(shortener.isSidecar(SPEC_SIDECAR));
		Assertions.assertFalse(shortener.isShortened(SPEC_SIDECAR));
		Assertions.assertEquals(SPEC_SIDECAR, shortener.sidecarFile(SPEC_SHORTENED));
	}

	@ParameterizedTest(name = "{0} is a plain entry")
	@ValueSource(strings = {"5TyvCyF255sRtfrIv83ucADQ.uvf", "dir.uvf", "WQ6QCEQX5BTXEPNQZNJLHDN52MADIVA4.shortened (1).uvf", "WQ6QCEQX5BTXEPNQZNJLHDN52MADIVA4.original (1).uvf", "wq6qceqx5btxepnqznjlhdn52madiva4.shortened.uvf",
			"WQ6QCEQX5BTXEPNQZNJLHDN52MADIVA.shortened.uvf", "WQ6QCEQX5BTXEPNQZNJLHDN52MADIVA1.shortened.uvf", "WQ6QCEQX5BTXEPNQZNJLHDN52MADIVA4.shortened", ""})
	void testPlainEntries(String entryName) {
		Assertions.assertFalse(shortener.isShortened(entryName));
		Assertions.assertFalse(shortener.isSidecar(entryName));
		Assertions.assertThrows(IllegalArgumentException.class, () -> shortener.sidecarFile(entryName));
		Assertions.assertThrows(IllegalArgumentException.class, () -> shortener.unshorten(entryName, SPEC_NAME.getBytes(UTF_8)));
	}

	@Test
	@DisplayName("unshorten verifies the sidecar against the entry name")
	void testUnshorten() {
		Assertions.assertEquals(SPEC_NAME, shortener.unshorten(SPEC_SHORTENED, SPEC_NAME.getBytes(UTF_8)));

		String otherName = repeat('b', 300) + ".uvf";
		Assertions.assertThrows(AuthenticationFailedException.class, () -> shortener.unshorten(SPEC_SHORTENED, otherName.getBytes(UTF_8)), "sidecar of another node");
		Assertions.assertThrows(AuthenticationFailedException.class, () -> shortener.unshorten(SPEC_SHORTENED, new byte[0]));
		Assertions.assertThrows(AuthenticationFailedException.class, () -> shortener.unshorten(SPEC_SHORTENED, (SPEC_NAME + "\n").getBytes(UTF_8)));
		Assertions.assertThrows(AuthenticationFailedException.class, () -> shortener.unshorten(SPEC_SHORTENED, "short.uvf".getBytes(UTF_8)));
	}

	@Test
	@DisplayName("a sidecar matching the hash is rejected if its name needs no shortening or is not UTF-8")
	void testUnshortenMatchingHash() throws NoSuchAlgorithmException {
		byte[] shortName = (repeat('a', 216) + ".uvf").getBytes(UTF_8);
		Assertions.assertThrows(AuthenticationFailedException.class, () -> shortener.unshorten(shortenedNameOf(shortName), shortName), "220 bytes need no shortening");
		byte[] longName = (repeat('a', 217) + ".uvf").getBytes(UTF_8);
		Assertions.assertEquals(repeat('a', 217) + ".uvf", shortener.unshorten(shortenedNameOf(longName), longName));

		byte[] invalidUtf8 = new byte[300];
		Arrays.fill(invalidUtf8, (byte) 0xFF);
		Assertions.assertThrows(AuthenticationFailedException.class, () -> shortener.unshorten(shortenedNameOf(invalidUtf8), invalidUtf8));
	}

	@Test
	@DisplayName("a disabled shortener passes everything through")
	void testDisabled() {
		NameShortener disabled = NameShortener.uvf(NameShortener.DISABLED);
		Assertions.assertEquals(-1, disabled.threshold());
		Assertions.assertNull(disabled.shorten(SPEC_NAME));
		Assertions.assertNull(disabled.shorten(SPEC_SHORTENED), "no reserved names without shortening");
		Assertions.assertFalse(disabled.isShortened(SPEC_SHORTENED));
		Assertions.assertFalse(disabled.isSidecar(SPEC_SIDECAR));
		Assertions.assertThrows(IllegalArgumentException.class, () -> disabled.sidecarFile(SPEC_SHORTENED));
		Assertions.assertThrows(IllegalArgumentException.class, () -> disabled.unshorten(SPEC_SHORTENED, SPEC_NAME.getBytes(UTF_8)));
	}

	@Test
	@DisplayName("threshold must be -1 or at least 46")
	void testThresholdValidation() {
		for (int invalid : new int[]{0, 1, 45, -2, Integer.MIN_VALUE}) {
			Assertions.assertThrows(IllegalArgumentException.class, () -> NameShortener.uvf(invalid));
		}
		Assertions.assertEquals(46, NameShortener.uvf(46).threshold());
		Assertions.assertEquals(Integer.MAX_VALUE, NameShortener.uvf(Integer.MAX_VALUE).threshold());
	}

	private static String shortenedNameOf(byte[] sidecarContents) throws NoSuchAlgorithmException {
		byte[] hash = MessageDigest.getInstance("SHA-256").digest(sidecarContents);
		return Base32.toBase32String(Arrays.copyOf(hash, 20)) + ".shortened.uvf";
	}

	private static String repeat(char c, int n) {
		char[] chars = new char[n];
		Arrays.fill(chars, c);
		return new String(chars);
	}

}
