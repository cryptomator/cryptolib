package org.cryptomator.cryptolib.packaged;

import org.cryptomator.cryptolib.api.Argon2Params;
import org.cryptomator.cryptolib.api.Cvf8LockedVault;
import org.cryptomator.cryptolib.api.Cvf8UnlockedVault;
import org.cryptomator.cryptolib.api.CvfMasterkey;
import org.cryptomator.cryptolib.api.LockedVault;
import org.cryptomator.cryptolib.api.NameShortener;
import org.cryptomator.cryptolib.api.ShortenedVaultNode;
import org.cryptomator.cryptolib.api.UnlockedVault;
import org.cryptomator.cryptolib.api.UvfKeyEncryptionKey;
import org.cryptomator.cryptolib.api.UvfLockedVault;
import org.cryptomator.cryptolib.api.UvfRecoveryKey;
import org.cryptomator.cryptolib.api.UvfUnlockedVault;
import org.cryptomator.cryptolib.api.VaultDirectory;
import org.cryptomator.cryptolib.api.VaultNode;
import org.cryptomator.cryptolib.examples.Cvf8Example;
import org.cryptomator.cryptolib.examples.UvfExample;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Smoke test of the public API through the packaged jar, run by the failsafe plugin after packaging: the JVM applies the multi-release layer with the sealed {@code LockedVault}/{@code UnlockedVault}
 * only to jars, so sealed-hierarchy mistakes surface here and not in the regular test run. Lives in its own package because the jar is sealed.
 */
class PackagedJarIT {

	private static final SecureRandom CSPRNG = new SecureRandom();
	// example from the UVF file name shortening specification
	private static final String SPEC_EXAMPLE_NAME = "cAp6_KasM-0d74bYyP1eOpweCA4NGgwjVfDGc6heAlXbLIVq2tMWskWpw-DGgyoC63Tjjs3weXCL3hjGfQlP_uJDocVs7kxvIKDEsnHk2GYEnbLGJgCsYcIahvxW9PLxkIXowBkEcaedqWWZNmW0Cv0e9-EaPHmiveg-uvH7Hdp0vxEbxqxRioJBDN1jmVVfV-rE8fCa6ijyBJXYem0IvMLYl4wNgi0G.uvf";
	// a cleartext name whose ciphertext name exceeds the shortening threshold of the examples
	private static final String LONG_NAME = String.join("", Collections.nCopies(20, "long name ")) + ".txt";
	private static final byte[] CONTENTS = "hello".getBytes(StandardCharsets.UTF_8);
	private static final Set<String> NAMES = new HashSet<>(Arrays.asList("short.txt", LONG_NAME));

	@Test
	@DisplayName("create, serialize, parse and unlock a CVF8 vault")
	void testCvf8() {
		byte[] config;
		byte[] ciphertext;
		VaultDirectory root;
		try (CvfMasterkey masterkey = CvfMasterkey.generate(CSPRNG); Cvf8UnlockedVault vault = Cvf8UnlockedVault.create(masterkey, 220, CSPRNG)) {
			config = vault.serializeConfig();
			ciphertext = vault.encryptFile("hello".getBytes(StandardCharsets.UTF_8));
			root = vault.rootDirectory();
			LockedVault locked = LockedVault.parse(config);
			Cvf8LockedVault cvf8 = Assertions.assertInstanceOf(Cvf8LockedVault.class, locked);
			try (UnlockedVault unlocked = cvf8.unlock(masterkey, CSPRNG)) {
				Assertions.assertEquals(root, unlocked.rootDirectory());
				Assertions.assertArrayEquals("hello".getBytes(StandardCharsets.UTF_8), unlocked.decryptFile(ciphertext));
			}
		}
	}

	@Test
	@DisplayName("create, serialize, parse and unlock a UVF vault")
	void testUvf() {
		UvfRecoveryKey recoveryKey = UvfRecoveryKey.generate(CSPRNG);
		byte[] config;
		byte[] ciphertext;
		String recoveryWords;
		VaultDirectory root;
		try (UvfUnlockedVault vault = UvfUnlockedVault.create(CSPRNG, UvfKeyEncryptionKey.password("secret", new Argon2Params(64, 1, 1)), recoveryKey, 220)) {
			config = vault.serializeConfig();
			recoveryWords = vault.serializedRecoveryKey();
			ciphertext = vault.encryptFile("hello".getBytes(StandardCharsets.UTF_8));
			root = vault.rootDirectory();
		}
		LockedVault locked = LockedVault.parse(config);
		UvfLockedVault uvf = Assertions.assertInstanceOf(UvfLockedVault.class, locked);
		try (UnlockedVault unlocked = uvf.unlock("secret", CSPRNG)) {
			Assertions.assertEquals(root, unlocked.rootDirectory());
			Assertions.assertArrayEquals("hello".getBytes(StandardCharsets.UTF_8), unlocked.decryptFile(ciphertext));
		}
		try (UnlockedVault recovered = locked.recover(recoveryWords, CSPRNG)) {
			Assertions.assertEquals(root, recovered.rootDirectory());
			Assertions.assertEquals(recoveryWords, recovered.serializedRecoveryKey());
		}
		Map<Integer, byte[]> pins;
		try (UvfUnlockedVault unlocked = uvf.unlock("secret", CSPRNG)) {
			pins = unlocked.seedDigests();
		}
		uvf.requireSeeds(pins.values()).unlock("secret", CSPRNG).close();
	}

	@Test
	@DisplayName("encrypt, shorten, unshorten and decrypt a long name through the public API")
	void testNameShortening() {
		StringBuilder longName = new StringBuilder();
		for (int i = 0; i < 200; i++) {
			longName.append('x');
		}
		try (CvfMasterkey masterkey = CvfMasterkey.generate(CSPRNG);
			 UnlockedVault cvf8 = Cvf8UnlockedVault.create(masterkey, 220, CSPRNG);
			 UnlockedVault uvf = UvfUnlockedVault.create(CSPRNG, UvfKeyEncryptionKey.password("secret", new Argon2Params(64, 1, 1)), UvfRecoveryKey.generate(CSPRNG), 220)) {
			for (UnlockedVault vault : new UnlockedVault[]{cvf8, uvf}) {
				NameShortener shortener = vault.nameShortener();
				VaultDirectory root = vault.rootDirectory();
				VaultNode node = root.encryptName(longName.toString());
				Assertions.assertNull(shortener.shorten(root.encryptName("short").name()));
				ShortenedVaultNode shortened = shortener.shorten(node.name());
				Assertions.assertNotNull(shortened);
				Assertions.assertTrue(shortener.isShortened(shortened.shortenedName()));
				Assertions.assertEquals(shortened.sidecarFile(), shortener.sidecarFile(shortened.shortenedName()));
				String ciphertextName = shortener.unshorten(shortened.shortenedName(), shortened.sidecarContents());
				Assertions.assertEquals(longName.toString(), root.decryptName(ciphertextName));
			}
		}
		Assertions.assertEquals("WQ6QCEQX5BTXEPNQZNJLHDN52MADIVA4.shortened.uvf", NameShortener.uvf(220).shorten(SPEC_EXAMPLE_NAME).shortenedName());
	}

	@Test
	@DisplayName("the CVF8 example stores, lists and reads entries with short and long names")
	void testCvf8Example(@TempDir Path vaultDir) throws IOException {
		try (Cvf8UnlockedVault vault = Cvf8Example.createVault(vaultDir, "secret", CSPRNG)) {
			Cvf8Example example = new Cvf8Example(vaultDir, vault);
			VaultDirectory root = vault.rootDirectory();
			VaultDirectory dir = example.createDirectory(root, LONG_NAME);
			example.writeFile(dir, "short.txt", CONTENTS);
			example.writeFile(dir, LONG_NAME, CONTENTS);

			Assertions.assertEquals(Collections.singletonList(LONG_NAME), example.list(root));
			Assertions.assertEquals(dir, example.directory(root, LONG_NAME));
			Assertions.assertEquals(NAMES, new HashSet<>(example.list(dir)));
			Assertions.assertArrayEquals(CONTENTS, example.readFile(dir, "short.txt"));
			Assertions.assertArrayEquals(CONTENTS, example.readFile(dir, LONG_NAME));
		}
		List<String> storedNames = storedNames(vaultDir);
		Assertions.assertEquals(2, storedNames.stream().filter(name -> name.endsWith(".c9s") && name.length() == 32).count());
		Assertions.assertEquals(2, storedNames.stream().filter("name.c9s"::equals).count());
		Assertions.assertTrue(storedNames.stream().allMatch(name -> name.length() <= 220));
	}

	@Test
	@DisplayName("the UVF example and the format-independent part of the CVF8 example are interchangeable")
	void testUvfExample(@TempDir Path vaultDir) throws IOException {
		try (UvfUnlockedVault vault = UvfExample.createVault(vaultDir, "secret", CSPRNG)) {
			UvfExample layered = new UvfExample(vaultDir, vault);
			Cvf8Example coupled = new Cvf8Example(vaultDir, vault);
			VaultDirectory root = vault.rootDirectory();
			VaultDirectory dir = layered.createDirectory(root, LONG_NAME);
			layered.writeFile(dir, "short.txt", CONTENTS);
			coupled.writeFile(dir, LONG_NAME, CONTENTS);
			VaultDirectory dir2 = coupled.createDirectory(dir, LONG_NAME + "2");
			layered.writeFile(dir2, LONG_NAME, CONTENTS);

			Assertions.assertEquals(Collections.singletonList(LONG_NAME), layered.list(root));
			Assertions.assertEquals(Collections.singletonList(LONG_NAME), coupled.list(root));
			Assertions.assertEquals(dir, layered.directory(root, LONG_NAME));
			Assertions.assertEquals(dir, coupled.directory(root, LONG_NAME));
			Set<String> names = new HashSet<>(NAMES);
			names.add(LONG_NAME + "2");
			Assertions.assertEquals(names, new HashSet<>(layered.list(dir)));
			Assertions.assertEquals(names, new HashSet<>(coupled.list(dir)));
			Assertions.assertArrayEquals(CONTENTS, layered.readFile(dir, "short.txt"));
			Assertions.assertArrayEquals(CONTENTS, coupled.readFile(dir, "short.txt"));
			Assertions.assertArrayEquals(CONTENTS, layered.readFile(dir, LONG_NAME));
			Assertions.assertArrayEquals(CONTENTS, coupled.readFile(dir, LONG_NAME));
			Assertions.assertEquals(dir2, layered.directory(dir, LONG_NAME + "2"));
			Assertions.assertEquals(dir2, coupled.directory(dir, LONG_NAME + "2"));
			Assertions.assertArrayEquals(CONTENTS, coupled.readFile(dir2, LONG_NAME));
		}
		List<String> storedNames = storedNames(vaultDir);
		Assertions.assertEquals(4, storedNames.stream().filter(name -> name.endsWith(".shortened.uvf") && name.length() == 46).count());
		Assertions.assertEquals(4, storedNames.stream().filter(name -> name.endsWith(".original.uvf") && name.length() == 45).count());
		Assertions.assertTrue(storedNames.stream().allMatch(name -> name.length() <= 220));
	}

	// the names of all files and directories below the given directory
	private static List<String> storedNames(Path vaultDir) throws IOException {
		try (Stream<Path> paths = Files.walk(vaultDir)) {
			return paths.filter(path -> !path.equals(vaultDir)).map(path -> path.getFileName().toString()).collect(Collectors.toList());
		}
	}

}
