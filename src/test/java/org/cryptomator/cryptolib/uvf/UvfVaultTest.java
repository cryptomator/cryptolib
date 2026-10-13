package org.cryptomator.cryptolib.uvf;

import com.google.gson.JsonParser;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObjectJSON;
import com.nimbusds.jose.util.Base64URL;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.LockedVault;
import org.cryptomator.cryptolib.api.UnsupportedVaultFormatException;
import org.cryptomator.cryptolib.api.UvfLockedVault;
import org.cryptomator.cryptolib.api.UvfRecipient;
import org.cryptomator.cryptolib.api.UvfUnlockedVault;
import org.cryptomator.cryptolib.api.VaultConfigLoadException;
import org.cryptomator.cryptolib.api.VaultDirectory;
import org.cryptomator.cryptolib.api.VaultFile;
import org.cryptomator.cryptolib.api.VaultKeyInvalidException;
import org.cryptomator.cryptolib.api.VaultNode;
import org.cryptomator.cryptolib.api.VaultReader;
import org.cryptomator.cryptolib.api.VaultWriter;
import org.cryptomator.cryptolib.common.InMemoryCiphertext;
import org.cryptomator.cryptolib.common.P384KeyPair;
import org.cryptomator.cryptolib.common.SecureRandomMock;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import static java.nio.charset.StandardCharsets.UTF_8;

public class UvfVaultTest {

	private static final SecureRandom CSPRNG = SecureRandomMock.PRNG_RANDOM;
	private static final byte[] UVF_MAGIC = {0x75, 0x76, 0x66, 0x00};
	private static final String SPEC_PROTECTED_HEADER = "eyJlbmMiOiJBMjU2R0NNIiwiY3R5IjoianNvbiIsImNyaXQiOlsidXZmLnNwZWMudmVyc2lvbiJdLCJ1dmYuc3BlYy52ZXJzaW9uIjoxfQ";

	// a vault backed by the spec's example payload (seeds HDm38i, gBryKw, QBsJFo)
	private static UvfVault specVault() {
		UvfSeeds seeds = UvfSeeds.fromDecryptedPayload(UvfSeedsTest.SPEC_PAYLOAD);
		return new UvfVault(seeds, new SecretKeySpec(new byte[32], "AES"), UvfMetadataCodec.newProtectedHeader(), new ArrayList<JWEObjectJSON.Recipient>(), CSPRNG, CSPRNG);
	}

	@Nested
	@DisplayName("spec example vault")
	public class SpecVault {

		private UvfVault vault;

		@BeforeEach
		public void setup() {
			vault = specVault();
		}

		@Test
		@DisplayName("root dir id and hash are deterministic")
		public void testRootDir() {
			VaultDirectory root = vault.rootDirectory();
			Assertions.assertEquals("5WEGzwKkAHPwVSjT2Brr3P3zLz7oMiNpMn/qBvht7eM=", Base64.getEncoder().encodeToString(root.dirId()));
			Assertions.assertEquals("RZK7ZH7KBXULNEKBMGX3CU42PGUIAIX4", root.dirHash());
			Assertions.assertEquals("d/RZ/K7ZH7KBXULNEKBMGX3CU42PGUIAIX4", root.dirPath());
			Assertions.assertEquals("d/RZ/K7ZH7KBXULNEKBMGX3CU42PGUIAIX4/dir.uvf", root.backupFilePath());
			Assertions.assertEquals(473544690, ((UvfDirectory) root).seedId());
		}

		@Test
		@DisplayName("dir.uvf of the root directory uses the initial seed")
		public void testRootDirUvf() {
			VaultDirectory root = vault.rootDirectory();
			byte[] dirUvf = root.encryptedMetadata();
			Assertions.assertEquals(128, dirUvf.length);
			Assertions.assertArrayEquals(UVF_MAGIC, Arrays.copyOf(dirUvf, 4));
			Assertions.assertArrayEquals(Base64.getUrlDecoder().decode("HDm38i"), Arrays.copyOfRange(dirUvf, 4, 8));
			Assertions.assertFalse(Arrays.equals(dirUvf, root.encryptedMetadata()), "each copy is encrypted independently");
			Assertions.assertEquals(root, vault.directory(dirUvf));
			Assertions.assertEquals(root, vault.directoryFromBackup(root.encryptedMetadataBackup()));
		}

		@Test
		@DisplayName("new directories use the latest seed")
		public void testNewDir() {
			VaultDirectory dir = vault.newDirectory();
			Assertions.assertEquals(32, dir.dirId().length);
			Assertions.assertEquals(1075513622, ((UvfDirectory) dir).seedId());
			Assertions.assertArrayEquals(Base64.getUrlDecoder().decode("QBsJFo"), Arrays.copyOfRange(dir.encryptedMetadata(), 4, 8));
			Assertions.assertEquals(dir, vault.directory(dir.encryptedMetadata()));
			Assertions.assertNotEquals(dir, vault.newDirectory());
		}

		@Test
		@DisplayName("files use the latest seed")
		public void testFileHeaderSeed() {
			byte[] ciphertext = vault.encryptFile("Hello, World!".getBytes(UTF_8));
			Assertions.assertArrayEquals(UVF_MAGIC, Arrays.copyOf(ciphertext, 4));
			Assertions.assertArrayEquals(Base64.getUrlDecoder().decode("QBsJFo"), Arrays.copyOfRange(ciphertext, 4, 8));
			Assertions.assertEquals(68 + 12 + 13 + 16, ciphertext.length);
			Assertions.assertArrayEquals("Hello, World!".getBytes(UTF_8), vault.decryptFile(ciphertext));
			try (VaultFile file = vault.openFile(ByteBuffer.wrap(ciphertext, 0, 68), ciphertext.length)) {
				Assertions.assertEquals(1075513622, file.seedId());
				Assertions.assertEquals(13, file.size());
			}
		}

		@Test
		@DisplayName("invalid dir.uvf contents")
		public void testInvalidDirUvf() {
			Assertions.assertThrows(IllegalArgumentException.class, () -> vault.directory(new byte[127]));
			byte[] tampered = vault.rootDirectory().encryptedMetadata();
			tampered[100] ^= 0x01;
			Assertions.assertThrows(AuthenticationFailedException.class, () -> vault.directory(tampered));
		}

		@Test
		@DisplayName("names round trip and are bound to the directory")
		public void testNames() throws IOException {
			VaultDirectory root = vault.rootDirectory();
			VaultNode node = root.encryptName("foo.txt");
			Assertions.assertTrue(node.name().endsWith(".uvf"));
			Assertions.assertFalse(node.isShortened());
			Assertions.assertEquals(node.name(), node.inflated());
			Assertions.assertEquals(node.name(), node.contentsFile());
			Assertions.assertEquals(node.name() + "/dir.uvf", node.dirFile());
			Assertions.assertEquals(node.name() + "/symlink.uvf", node.symlinkFile());
			Assertions.assertThrows(IllegalStateException.class, node::inflatedNameFile);
			Assertions.assertEquals("foo.txt", root.decryptName(node.name()));
			Assertions.assertEquals("foo.txt", root.decryptName(node.name(), path -> {
				throw new IOException("must not be called");
			}));
			Assertions.assertThrows(AuthenticationFailedException.class, () -> vault.newDirectory().decryptName(node.name()));
			Assertions.assertThrows(IllegalArgumentException.class, () -> root.decryptName("vault.uvf.bkup"));
			Assertions.assertThrows(AuthenticationFailedException.class, () -> root.decryptName("dir.uvf")); // ends with .uvf but isn't a ciphertext name
			Assertions.assertEquals(146, vault.maxCleartextNameLength(220));
		}

		@Test
		@DisplayName("create and resolve subdirectory and symlink via callbacks")
		public void testCreateNodes() throws IOException {
			Map<String, byte[]> files = new HashMap<>();
			VaultWriter writer = files::put;
			VaultReader reader = files::get;
			VaultDirectory root = vault.rootDirectory();
			root.writeMetadataBackup(writer);
			VaultDirectory child = vault.newDirectory();
			VaultNode dirNode = root.encryptName("sub");
			dirNode.createDirectory(child, writer);
			VaultNode linkNode = root.encryptName("link");
			linkNode.createSymlink("../target", writer);
			Assertions.assertEquals(4, files.size());
			Assertions.assertTrue(files.containsKey(root.dirPath() + "/" + dirNode.dirFile()));
			Assertions.assertTrue(files.containsKey(child.backupFilePath()));
			Assertions.assertEquals(child, dirNode.directory(reader));
			Assertions.assertEquals("../target", linkNode.symlinkTarget(reader));
			Assertions.assertEquals("sub", root.decryptName(dirNode.name(), reader));
		}

		@Test
		@DisplayName("symlink target normalized to NFC")
		public void testSymlinkNfc() {
			Assertions.assertEquals("über", vault.decryptSymlinkTarget(vault.encryptSymlinkTarget("über")));
		}

	}

	@Nested
	@DisplayName("files")
	public class Files {

		private UvfVault vault;

		@BeforeEach
		public void setup() {
			vault = specVault();
		}

		@ParameterizedTest(name = "round trip of {0} bytes incl. EOF chunk rule")
		@ValueSource(ints = {0, 1, 32739, 32740, 32741, 65480, 100000})
		public void testRoundTrip(int size) throws IOException {
			byte[] cleartext = new byte[size];
			new Random(size).nextBytes(cleartext);
			byte[] ciphertext = vault.encryptFile(cleartext);
			Assertions.assertEquals(vault.ciphertextSize(size), ciphertext.length);
			long fullChunks = size / 32740;
			int remainder = size % 32740;
			Assertions.assertEquals(68 + fullChunks * 32768 + (remainder == 0 ? 28 : remainder + 28), ciphertext.length, "EOF chunk present iff size is a multiple of 32740");
			Assertions.assertArrayEquals(cleartext, vault.decryptFile(ciphertext));

			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			try (WritableByteChannel ch = vault.encryptingChannel(Channels.newChannel(baos))) {
				ch.write(ByteBuffer.wrap(cleartext));
			}
			Assertions.assertEquals(ciphertext.length, baos.size());
			Assertions.assertArrayEquals(cleartext, vault.decryptFile(baos.toByteArray()));

			ByteBuffer pulled = ByteBuffer.allocate(ciphertext.length + 1);
			try (ReadableByteChannel ch = vault.encryptingChannel(Channels.newChannel(new ByteArrayInputStream(cleartext)))) {
				Assertions.assertEquals(ciphertext.length, ch.read(pulled));
			}

			ByteBuffer decrypted = ByteBuffer.allocate(size + 1);
			try (ReadableByteChannel ch = vault.decryptingChannel(Channels.newChannel(new ByteArrayInputStream(ciphertext)))) {
				int read = ch.read(decrypted);
				Assertions.assertEquals(size == 0 ? -1 : size, read);
			}
			Assertions.assertArrayEquals(cleartext, Arrays.copyOf(decrypted.array(), size));
		}

		@Test
		@DisplayName("missing EOF chunk is detected")
		public void testMissingEofChunk() {
			byte[] ciphertext = vault.encryptFile(new byte[32740]);
			byte[] truncated = Arrays.copyOf(ciphertext, 68 + 32768);
			Assertions.assertThrows(IllegalArgumentException.class, () -> vault.decryptFile(truncated));
			Assertions.assertThrows(IllegalArgumentException.class, () -> vault.cleartextSize(truncated.length));
			Assertions.assertThrows(IOException.class, () -> {
				try (ReadableByteChannel ch = vault.decryptingChannel(Channels.newChannel(new ByteArrayInputStream(truncated)))) {
					ch.read(ByteBuffer.allocate(40000));
				}
			});
		}

		@Test
		@DisplayName("range access maintains the EOF chunk")
		public void testRangeAccessEofChunk() throws IOException {
			InMemoryCiphertext ciphertext = new InMemoryCiphertext();
			try (VaultFile file = vault.createFile()) {
				file.write(0, ByteBuffer.wrap(new byte[32740]), ciphertext, ciphertext);
				Assertions.assertEquals(68 + 32768 + 28, ciphertext.size());
				Assertions.assertArrayEquals(new byte[32740], vault.decryptFile(ciphertext.toByteArray()));

				file.write(32740, ByteBuffer.wrap(new byte[]{1}), ciphertext, ciphertext); // EOF chunk becomes a data chunk
				Assertions.assertEquals(68 + 32768 + 29, ciphertext.size());
				byte[] expected = new byte[32741];
				expected[32740] = 1;
				Assertions.assertArrayEquals(expected, vault.decryptFile(ciphertext.toByteArray()));

				file.truncate(32740, ciphertext, ciphertext);
				ciphertext.truncate(vault.ciphertextSize(32740));
				Assertions.assertEquals(68 + 32768 + 28, ciphertext.size());
				Assertions.assertArrayEquals(new byte[32740], vault.decryptFile(ciphertext.toByteArray()));

				file.truncate(0, ciphertext, ciphertext);
				ciphertext.truncate(vault.ciphertextSize(0));
				Assertions.assertEquals(96, ciphertext.size());
				Assertions.assertArrayEquals(new byte[0], vault.decryptFile(ciphertext.toByteArray()));
			}
		}

	}

	@Nested
	@DisplayName("vault.uvf")
	public class Config {

		@Test
		@DisplayName("spec example protected header is accepted")
		public void testSpecProtectedHeader() throws Exception {
			JWEHeader header = JWEHeader.parse(new Base64URL(SPEC_PROTECTED_HEADER));
			Assertions.assertEquals(1, UvfMetadataCodec.specVersion(header));
			Assertions.assertEquals(JsonParser.parseString(header.toString()), JsonParser.parseString(UvfMetadataCodec.newProtectedHeader().toString()));
		}

		@Test
		@DisplayName("create vault with password and EC recipients, serialize, unlock with each")
		public void testCreateAndUnlock() {
			P384KeyPair userKey = P384KeyPair.generate();
			byte[] config;
			VaultDirectory root;
			try (UvfUnlockedVault created = UvfUnlockedVault.create(CSPRNG)) {
				Assertions.assertEquals("vault.uvf", created.configFileName());
				Assertions.assertThrows(IllegalStateException.class, created::serializeConfig);
				created.addPasswordRecipient("org.example.password", "correct horse battery staple", 1000);
				created.addEcdhRecipient("org.example.user.42", userKey.getPublic());
				created.addKeyWrapRecipient("org.example.kek", new SecretKeySpec(new byte[32], "AES"));
				Assertions.assertEquals(3, created.recipients().size());
				config = created.serializeConfig();
				root = created.rootDirectory();
			}

			LockedVault locked = LockedVault.parse(config);
			UvfLockedVault uvf = Assertions.assertInstanceOf(UvfLockedVault.class, locked);
			Assertions.assertEquals(1, uvf.allegedSpecVersion());
			Assertions.assertArrayEquals(config, uvf.encoded());
			Assertions.assertEquals(3, uvf.recipients().size());
			UvfRecipient pw = uvf.recipients().get(0);
			UvfRecipient ec = uvf.recipients().get(1);
			UvfRecipient kek = uvf.recipients().get(2);
			Assertions.assertEquals("org.example.password", pw.kid());
			Assertions.assertEquals("PBES2-HS512+A256KW", pw.alg());
			Assertions.assertEquals(1000L, ((Number) pw.header().get("p2c")).longValue());
			Assertions.assertNotNull(pw.header().get("p2s"));
			Assertions.assertEquals("ECDH-ES+A256KW", ec.alg());
			Assertions.assertNotNull(ec.header().get("epk"));
			Assertions.assertEquals("A256KW", kek.alg());

			try (UvfUnlockedVault unlocked = uvf.unlock(pw, "correct horse battery staple", CSPRNG)) {
				Assertions.assertEquals(root, unlocked.rootDirectory());
				Assertions.assertEquals(1, unlocked.seedIds().size());
				Assertions.assertEquals(unlocked.initialSeedId(), unlocked.latestSeedId());
			}
			try (UvfUnlockedVault unlocked = uvf.unlock(ec, userKey.getPrivate(), CSPRNG)) {
				Assertions.assertEquals(root, unlocked.rootDirectory());
			}
			try (UvfUnlockedVault unlocked = uvf.unlock(kek, new SecretKeySpec(new byte[32], "AES"), CSPRNG)) {
				Assertions.assertEquals(root, unlocked.rootDirectory());
			}
		}

		@Test
		@DisplayName("wrong secrets are rejected")
		public void testWrongSecrets() {
			P384KeyPair userKey = P384KeyPair.generate();
			byte[] config;
			try (UvfUnlockedVault created = UvfUnlockedVault.create(CSPRNG)) {
				created.addPasswordRecipient("org.example.password", "secret", 1000);
				created.addEcdhRecipient("org.example.user.42", userKey.getPublic());
				created.addKeyWrapRecipient("org.example.kek", new SecretKeySpec(new byte[32], "AES"));
				config = created.serializeConfig();
			}
			UvfLockedVault uvf = (UvfLockedVault) LockedVault.parse(config);
			UvfRecipient pw = uvf.recipients().get(0);
			UvfRecipient ec = uvf.recipients().get(1);
			UvfRecipient kek = uvf.recipients().get(2);
			Assertions.assertThrows(VaultKeyInvalidException.class, () -> uvf.unlock(pw, "wrong", CSPRNG));
			Assertions.assertThrows(VaultKeyInvalidException.class, () -> uvf.unlock(ec, P384KeyPair.generate().getPrivate(), CSPRNG));
			byte[] wrongKek = new byte[32];
			wrongKek[0] = 1;
			Assertions.assertThrows(VaultKeyInvalidException.class, () -> uvf.unlock(kek, new SecretKeySpec(wrongKek, "AES"), CSPRNG));
			// recipient / secret type mismatch:
			Assertions.assertThrows(VaultConfigLoadException.class, () -> uvf.unlock(ec, "secret", CSPRNG));
			Assertions.assertThrows(VaultConfigLoadException.class, () -> uvf.unlock(pw, userKey.getPrivate(), CSPRNG));
			Assertions.assertThrows(VaultConfigLoadException.class, () -> uvf.unlock(pw, new SecretKeySpec(new byte[32], "AES"), CSPRNG));
		}

		@Test
		@DisplayName("key rotation and recipient management survive serialization")
		public void testRotation() {
			byte[] config;
			VaultDirectory rootBefore;
			byte[] fileBefore;
			try (UvfUnlockedVault created = UvfUnlockedVault.create(CSPRNG)) {
				created.addPasswordRecipient("org.example.password", "secret", 1000);
				config = created.serializeConfig();
				rootBefore = created.rootDirectory();
				fileBefore = created.encryptFile("before".getBytes(UTF_8));
			}
			int newSeed;
			UvfLockedVault locked = (UvfLockedVault) LockedVault.parse(config);
			try (UvfUnlockedVault unlocked = locked.unlock(locked.recipients().get(0), "secret", CSPRNG)) {
				newSeed = unlocked.addSeed();
				Assertions.assertEquals(newSeed, unlocked.latestSeedId());
				Assertions.assertEquals(2, unlocked.seedIds().size());
				Assertions.assertEquals(rootBefore, unlocked.rootDirectory());
				Assertions.assertArrayEquals(Base64.getUrlDecoder().decode(UvfSeeds.encodeSeedId(newSeed)), Arrays.copyOfRange(unlocked.encryptFile(new byte[1]), 4, 8));
				unlocked.addPasswordRecipient("org.example.second", "other", 1000);
				unlocked.removeRecipient("org.example.password");
				Assertions.assertThrows(IllegalArgumentException.class, () -> unlocked.removeRecipient("org.example.password"));
				Assertions.assertThrows(IllegalStateException.class, () -> unlocked.removeRecipient("org.example.second"));
				config = unlocked.serializeConfig();
			}
			UvfLockedVault relocked = (UvfLockedVault) LockedVault.parse(config);
			Assertions.assertEquals(1, relocked.recipients().size());
			Assertions.assertEquals("org.example.second", relocked.recipients().get(0).kid());
			try (UvfUnlockedVault unlocked = relocked.unlock(relocked.recipients().get(0), "other", CSPRNG)) {
				Assertions.assertEquals(newSeed, unlocked.latestSeedId());
				Assertions.assertEquals(rootBefore, unlocked.rootDirectory());
				Assertions.assertArrayEquals("before".getBytes(UTF_8), unlocked.decryptFile(fileBefore), "old seed still decrypts old files");
			}
		}

		@Test
		@DisplayName("custom fields are preserved")
		public void testCustomFields() {
			byte[] config;
			try (UvfVault vault = specVault()) {
				vault.addPasswordRecipient("org.example.password", "secret", 1000);
				Assertions.assertEquals(42L, vault.customFields().get("org.example.customfield"));
				config = vault.serializeConfig();
			}
			UvfLockedVault locked = (UvfLockedVault) LockedVault.parse(config);
			try (UvfUnlockedVault unlocked = locked.unlock(locked.recipients().get(0), "secret", CSPRNG)) {
				Assertions.assertEquals(42L, unlocked.customFields().get("org.example.customfield"));
				Assertions.assertEquals(473544690, unlocked.initialSeedId());
				Assertions.assertEquals(1075513622, unlocked.latestSeedId());
			}
		}

		@Test
		@DisplayName("serialized config has the structure required by the spec")
		public void testSerializedStructure() throws Exception {
			byte[] config;
			try (UvfVault vault = specVault()) {
				vault.addPasswordRecipient("org.example.password", "secret", 1000);
				config = vault.serializeConfig();
			}
			JWEObjectJSON jwe = JWEObjectJSON.parse(new String(config, StandardCharsets.UTF_8));
			Assertions.assertEquals("A256GCM", jwe.getHeader().getEncryptionMethod().getName());
			Assertions.assertEquals("json", jwe.getHeader().getContentType());
			Assertions.assertNull(jwe.getHeader().getAlgorithm());
			Assertions.assertNull(jwe.getHeader().getCompressionAlgorithm());
			Assertions.assertEquals(1, jwe.getRecipients().size());
			Assertions.assertEquals("PBES2-HS512+A256KW", jwe.getRecipients().get(0).getUnprotectedHeader().getParam("alg"));
			Assertions.assertTrue(new String(config, StandardCharsets.UTF_8).contains("\"recipients\""));
		}

		@ParameterizedTest(name = "rejected protected header: {0}")
		@ValueSource(strings = { //
				"{\"enc\":\"A256GCM\",\"cty\":\"json\",\"crit\":[\"uvf.spec.version\"],\"uvf.spec.version\":2}", //
				"{\"enc\":\"A256GCM\",\"cty\":\"json\",\"crit\":[\"uvf.spec.version\",\"com.example.foo\"],\"uvf.spec.version\":1,\"com.example.foo\":true}", //
				"{\"enc\":\"A256GCM\",\"cty\":\"json\",\"uvf.spec.version\":1}", //
				"{\"enc\":\"A128GCM\",\"cty\":\"json\",\"crit\":[\"uvf.spec.version\"],\"uvf.spec.version\":1}", //
				"{\"enc\":\"A256GCM\",\"zip\":\"DEF\",\"cty\":\"json\",\"crit\":[\"uvf.spec.version\"],\"uvf.spec.version\":1}", //
				"{\"alg\":\"A256KW\",\"enc\":\"A256GCM\",\"cty\":\"json\",\"crit\":[\"uvf.spec.version\"],\"uvf.spec.version\":1}" //
		})
		public void testRejectedProtectedHeaders(String protectedHeaderJson) {
			String json = "{\"protected\":\"" + Base64URL.encode(protectedHeaderJson) + "\",\"iv\":\"AAAAAAAAAAAAAAAA\",\"ciphertext\":\"AAAA\",\"tag\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"recipients\":[{\"header\":{\"alg\":\"A256KW\",\"kid\":\"x\"},\"encrypted_key\":\"AAAA\"}]}";
			Class<? extends org.cryptomator.cryptolib.api.CryptoException> expected = protectedHeaderJson.contains("\"uvf.spec.version\":2") ? UnsupportedVaultFormatException.class : VaultConfigLoadException.class;
			Assertions.assertThrows(expected, () -> LockedVault.parse(json.getBytes(UTF_8)));
		}

		@Test
		@DisplayName("garbage and empty recipients are rejected")
		public void testGarbage() {
			Assertions.assertThrows(VaultConfigLoadException.class, () -> LockedVault.parse("{\"foo\":1}".getBytes(UTF_8)));
			Assertions.assertThrows(VaultConfigLoadException.class, () -> LockedVault.parse("{".getBytes(UTF_8)));
		}

		@Test
		@DisplayName("foreign recipient object is rejected")
		public void testForeignRecipient() {
			byte[] config;
			try (UvfUnlockedVault created = UvfUnlockedVault.create(CSPRNG)) {
				created.addPasswordRecipient("org.example.password", "secret", 1000);
				config = created.serializeConfig();
			}
			UvfLockedVault a = (UvfLockedVault) LockedVault.parse(config);
			UvfLockedVault b = (UvfLockedVault) LockedVault.parse(config);
			Assertions.assertThrows(IllegalArgumentException.class, () -> a.unlock(b.recipients().get(0), "secret", CSPRNG));
		}

		@Test
		@DisplayName("iteration count limits")
		public void testIterationCountLimits() {
			try (UvfUnlockedVault created = UvfUnlockedVault.create(CSPRNG)) {
				Assertions.assertThrows(IllegalArgumentException.class, () -> created.addPasswordRecipient("x", "secret", 999));
				Assertions.assertThrows(IllegalArgumentException.class, () -> created.addPasswordRecipient("x", "secret", 1_000_001));
			}
		}

	}

	@Test
	@DisplayName("destroying the vault destroys the seeds")
	public void testDestroy() {
		UvfVault vault = specVault();
		vault.close();
		Assertions.assertTrue(vault.isDestroyed());
		Assertions.assertThrows(IllegalStateException.class, vault::rootDirectory);
		Assertions.assertThrows(IllegalStateException.class, vault::createFile);
	}

}
