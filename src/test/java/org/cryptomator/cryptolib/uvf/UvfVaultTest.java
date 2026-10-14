package org.cryptomator.cryptolib.uvf;

import com.google.gson.JsonParser;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObjectJSON;
import com.nimbusds.jose.UnprotectedHeader;
import com.nimbusds.jose.crypto.MultiDecrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import org.cryptomator.cryptolib.api.Argon2Params;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.LockedVault;
import org.cryptomator.cryptolib.api.UnlockedVault;
import org.cryptomator.cryptolib.api.UnsupportedVaultFormatException;
import org.cryptomator.cryptolib.api.UvfLockedVault;
import org.cryptomator.cryptolib.api.UvfUnlockedVault;
import org.cryptomator.cryptolib.api.VaultConfigLoadException;
import org.cryptomator.cryptolib.api.VaultDirectory;
import org.cryptomator.cryptolib.api.VaultFile;
import org.cryptomator.cryptolib.api.VaultKeyInvalidException;
import org.cryptomator.cryptolib.api.VaultNode;
import org.cryptomator.cryptolib.api.VaultReader;
import org.cryptomator.cryptolib.api.VaultWriter;
import org.cryptomator.cryptolib.common.InMemoryCiphertext;
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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import static java.nio.charset.StandardCharsets.UTF_8;

public class UvfVaultTest {

	private static final SecureRandom CSPRNG = SecureRandomMock.PRNG_RANDOM;
	private static final byte[] UVF_MAGIC = {0x75, 0x76, 0x66, 0x00};
	private static final String SPEC_PROTECTED_HEADER = "eyJlbmMiOiJBMjU2R0NNIiwiY3R5IjoianNvbiIsImNyaXQiOlsidXZmLnNwZWMudmVyc2lvbiJdLCJ1dmYuc3BlYy52ZXJzaW9uIjoxfQ";

	private static KeyPair ecKeyPair() {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
			generator.initialize(new ECGenParameterSpec("secp384r1"));
			return generator.generateKeyPair();
		} catch (java.security.GeneralSecurityException e) {
			throw new IllegalStateException(e);
		}
	}

	// a vault backed by the spec's example payload (seeds HDm38i, gBryKw, QBsJFo)
	private static UvfVault specVault() {
		UvfSeeds seeds = UvfSeeds.fromDecryptedPayload(UvfSeedsTest.SPEC_PAYLOAD);
		return new UvfVault(seeds, UvfMetadataCodec.newProtectedHeader(), null, Collections.<String, Object>emptyMap(), null, CSPRNG, CSPRNG);
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

		private final Argon2Params CHEAP = new Argon2Params(64, 1, 1);

		@Test
		@DisplayName("spec example protected header is accepted")
		public void testSpecProtectedHeader() throws Exception {
			JWEHeader header = JWEHeader.parse(new Base64URL(SPEC_PROTECTED_HEADER));
			Assertions.assertEquals(1, UvfMetadataCodec.specVersion(header));
			Assertions.assertEquals(JsonParser.parseString(header.toString()), JsonParser.parseString(UvfMetadataCodec.newProtectedHeader().toString()));
		}

		@Test
		@DisplayName("create a password vault, serialize, unlock with password and recovery key")
		public void testPasswordVault() {
			KeyPair recoveryKey = ecKeyPair();
			byte[] config;
			VaultDirectory root;
			try (UvfUnlockedVault created = UvfUnlockedVault.create(CSPRNG)) {
				Assertions.assertEquals("vault.uvf", created.configFileName());
				Assertions.assertNull(created.keyEncryptionKid());
				Assertions.assertNull(created.recoveryKid());
				Assertions.assertThrows(IllegalStateException.class, created::serializeConfig);
				created.setPassword("correct horse battery staple", CHEAP);
				Assertions.assertThrows(IllegalStateException.class, created::serializeConfig, "recovery key missing");
				created.setRecoveryKey((ECPublicKey) recoveryKey.getPublic());
				Assertions.assertEquals("org.cryptomator.password.argon2", created.keyEncryptionKid());
				Assertions.assertTrue(created.recoveryKid().startsWith("org.cryptomator.hub.recoverykey."));
				config = created.serializeConfig();
				root = created.rootDirectory();
			}

			LockedVault locked = LockedVault.parse(config);
			UvfLockedVault uvf = Assertions.assertInstanceOf(UvfLockedVault.class, locked);
			Assertions.assertEquals(1, uvf.allegedSpecVersion());
			Assertions.assertArrayEquals(config, uvf.encoded());
			Assertions.assertEquals("org.cryptomator.password.argon2", uvf.keyEncryptionKid());
			Assertions.assertTrue(uvf.recoveryKid().startsWith("org.cryptomator.hub.recoverykey."));

			try (UvfUnlockedVault unlocked = uvf.unlock("correct horse battery staple", CSPRNG)) {
				Assertions.assertEquals(root, unlocked.rootDirectory());
				Assertions.assertEquals(1, unlocked.seedIds().size());
				Assertions.assertEquals(unlocked.initialSeedId(), unlocked.latestSeedId());
				Assertions.assertEquals("org.cryptomator.password.argon2", unlocked.keyEncryptionKid());
				Assertions.assertEquals(uvf.recoveryKid(), unlocked.recoveryKid());
			}
			try (UvfUnlockedVault recovered = uvf.recover((ECPrivateKey) recoveryKey.getPrivate(), CSPRNG)) {
				Assertions.assertEquals(root, recovered.rootDirectory());
				Assertions.assertNull(recovered.keyEncryptionKid());
				Assertions.assertEquals(uvf.recoveryKid(), recovered.recoveryKid());
			}
			Assertions.assertThrows(VaultKeyInvalidException.class, () -> uvf.unlock("wrong", CSPRNG));
			Assertions.assertThrows(VaultKeyInvalidException.class, () -> uvf.recover((ECPrivateKey) ecKeyPair().getPrivate(), CSPRNG));
			Assertions.assertThrows(VaultConfigLoadException.class, () -> uvf.unlock(new SecretKeySpec(new byte[32], "AES"), CSPRNG), "not a member key vault");
		}

		@Test
		@DisplayName("create a member key vault, serialize, unlock with member key")
		public void testMemberKeyVault() {
			SecretKeySpec memberKey = new SecretKeySpec(new byte[32], "AES");
			byte[] config;
			try (UvfUnlockedVault created = UvfUnlockedVault.create(CSPRNG)) {
				Assertions.assertThrows(IllegalArgumentException.class, () -> created.setMemberKey(new SecretKeySpec(new byte[16], "AES")));
				created.setMemberKey(memberKey);
				created.setRecoveryKey((ECPublicKey) ecKeyPair().getPublic());
				config = created.serializeConfig();
			}
			UvfLockedVault uvf = (UvfLockedVault) LockedVault.parse(config);
			Assertions.assertEquals("org.cryptomator.hub.memberkey", uvf.keyEncryptionKid());
			uvf.unlock(memberKey, CSPRNG).close();
			byte[] wrong = new byte[32];
			wrong[0] = 1;
			Assertions.assertThrows(VaultKeyInvalidException.class, () -> uvf.unlock(new SecretKeySpec(wrong, "AES"), CSPRNG));
			Assertions.assertThrows(VaultConfigLoadException.class, () -> uvf.unlock("password", CSPRNG), "not a password vault");
		}

		@Test
		@DisplayName("key rotation and re-encryption survive serialization")
		public void testRotation() {
			KeyPair recoveryKey = ecKeyPair();
			byte[] config;
			VaultDirectory rootBefore;
			byte[] fileBefore;
			try (UvfUnlockedVault created = UvfUnlockedVault.create(CSPRNG)) {
				created.setPassword("secret", CHEAP);
				created.setRecoveryKey((ECPublicKey) recoveryKey.getPublic());
				config = created.serializeConfig();
				rootBefore = created.rootDirectory();
				fileBefore = created.encryptFile("before".getBytes(UTF_8));
			}
			int newSeed;
			byte[] rotated;
			UvfLockedVault locked = (UvfLockedVault) LockedVault.parse(config);
			try (UvfUnlockedVault unlocked = locked.unlock("secret", CSPRNG)) {
				newSeed = unlocked.addSeed();
				Assertions.assertEquals(newSeed, unlocked.latestSeedId());
				Assertions.assertEquals(2, unlocked.seedIds().size());
				Assertions.assertEquals(rootBefore, unlocked.rootDirectory());
				Assertions.assertArrayEquals(Base64.getUrlDecoder().decode(UvfSeeds.encodeSeedId(newSeed)), Arrays.copyOfRange(unlocked.encryptFile(new byte[1]), 4, 8));
				rotated = unlocked.serializeConfig(); // re-encrypted with the retained password-derived key and the recovery key from the file
			}
			Assertions.assertFalse(Arrays.equals(config, rotated));
			UvfLockedVault relocked = (UvfLockedVault) LockedVault.parse(rotated);
			Assertions.assertEquals(locked.recoveryKid(), relocked.recoveryKid());
			for (UvfUnlockedVault unlocked : new UvfUnlockedVault[]{relocked.unlock("secret", CSPRNG), relocked.recover((ECPrivateKey) recoveryKey.getPrivate(), CSPRNG)}) {
				Assertions.assertEquals(newSeed, unlocked.latestSeedId());
				Assertions.assertEquals(rootBefore, unlocked.rootDirectory());
				Assertions.assertArrayEquals("before".getBytes(UTF_8), unlocked.decryptFile(fileBefore), "old seed still decrypts old files");
				unlocked.close();
			}
		}

		@Test
		@DisplayName("password change and recovery flow")
		public void testPasswordChangeAndRecovery() {
			KeyPair recoveryKey = ecKeyPair();
			KeyPair newRecoveryKey = ecKeyPair();
			byte[] config;
			try (UvfUnlockedVault created = UvfUnlockedVault.create(CSPRNG)) {
				created.setPassword("old", CHEAP);
				created.setRecoveryKey((ECPublicKey) recoveryKey.getPublic());
				config = created.serializeConfig();
			}
			// password change
			try (UvfUnlockedVault unlocked = ((UvfLockedVault) LockedVault.parse(config)).unlock("old", CSPRNG)) {
				unlocked.setPassword("new", CHEAP);
				config = unlocked.serializeConfig();
			}
			UvfLockedVault changed = (UvfLockedVault) LockedVault.parse(config);
			Assertions.assertThrows(VaultKeyInvalidException.class, () -> changed.unlock("old", CSPRNG));
			changed.unlock("new", CSPRNG).close();
			// recovery: forgotten password, set a member key and a new recovery key
			SecretKeySpec memberKey = new SecretKeySpec(new byte[32], "AES");
			try (UvfUnlockedVault recovered = changed.recover((ECPrivateKey) recoveryKey.getPrivate(), CSPRNG)) {
				Assertions.assertThrows(IllegalStateException.class, recovered::serializeConfig, "no key encryption key after recovery");
				recovered.setMemberKey(memberKey);
				recovered.setRecoveryKey((ECPublicKey) newRecoveryKey.getPublic());
				Assertions.assertNotEquals(changed.recoveryKid(), recovered.recoveryKid());
				config = recovered.serializeConfig();
			}
			UvfLockedVault recovered = (UvfLockedVault) LockedVault.parse(config);
			Assertions.assertEquals("org.cryptomator.hub.memberkey", recovered.keyEncryptionKid());
			Assertions.assertThrows(VaultConfigLoadException.class, () -> recovered.unlock("new", CSPRNG));
			Assertions.assertThrows(VaultKeyInvalidException.class, () -> recovered.recover((ECPrivateKey) recoveryKey.getPrivate(), CSPRNG));
			recovered.unlock(memberKey, CSPRNG).close();
			recovered.recover((ECPrivateKey) newRecoveryKey.getPrivate(), CSPRNG).close();
		}

		@Test
		@DisplayName("recovery key as words: create, serialize, recover, re-encode")
		public void testRecoveryKeyWords() throws Exception {
			KeyPair recoveryKey = UvfUnlockedVault.generateRecoveryKey(CSPRNG);
			Assertions.assertEquals("secp384r1", ((ECPublicKey) recoveryKey.getPublic()).getParams().toString().substring(0, 9));
			byte[] config;
			String words;
			try (UvfUnlockedVault created = UvfUnlockedVault.create(CSPRNG)) {
				Assertions.assertThrows(IllegalStateException.class, created::serializedRecoveryKey, "no recovery key yet");
				created.setPassword("secret", CHEAP);
				created.setRecoveryKey(recoveryKey);
				words = created.serializedRecoveryKey();
				Assertions.assertEquals(126, words.split(" ").length);
				Assertions.assertEquals(words, created.serializedRecoveryKey(), "deterministic");
				config = created.serializeConfig();
			}
			String json = new String(config, UTF_8);
			Assertions.assertFalse(json.contains("\"d\""), "private key must not be serialized");
			Assertions.assertTrue(json.contains("\"x\""), "public key is serialized");

			UvfLockedVault locked = (UvfLockedVault) LockedVault.parse(config);
			try (UvfUnlockedVault unlocked = locked.unlock("secret", CSPRNG)) {
				Assertions.assertThrows(IllegalStateException.class, unlocked::serializedRecoveryKey, "password unlock knows the public key only");
			}
			try (UvfUnlockedVault recovered = locked.recover(words, CSPRNG)) {
				Assertions.assertEquals(locked.recoveryKid(), recovered.recoveryKid());
				Assertions.assertNull(recovered.keyEncryptionKid());
				Assertions.assertEquals(words, recovered.serializedRecoveryKey(), "recovery retains the key pair");
				recovered.setRecoveryKey((ECPublicKey) recoveryKey.getPublic());
				Assertions.assertThrows(IllegalStateException.class, recovered::serializedRecoveryKey, "public-only setter drops the private key");
			}
			try (UnlockedVault recovered = ((LockedVault) locked).recover(words, CSPRNG)) {
				Assertions.assertInstanceOf(UvfUnlockedVault.class, recovered);
			}
			try (UvfUnlockedVault recovered = locked.recover((ECPrivateKey) recoveryKey.getPrivate(), CSPRNG)) {
				Assertions.assertEquals(words, recovered.serializedRecoveryKey());
			}

			// wrong or malformed keys
			String otherWords;
			try (UvfUnlockedVault other = UvfUnlockedVault.create(CSPRNG)) {
				other.setRecoveryKey(UvfUnlockedVault.generateRecoveryKey(CSPRNG));
				otherWords = other.serializedRecoveryKey();
			}
			Assertions.assertThrows(VaultKeyInvalidException.class, () -> locked.recover(otherWords, CSPRNG));
			Assertions.assertThrows(IllegalArgumentException.class, () -> locked.recover("hallo bonjour", CSPRNG));
			Assertions.assertThrows(IllegalArgumentException.class, () -> locked.recover(words.substring(words.indexOf(' ') + 1), CSPRNG), "one word missing");
			try (UvfUnlockedVault created = UvfUnlockedVault.create(CSPRNG)) {
				KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
				generator.initialize(new ECGenParameterSpec("secp256r1"));
				Assertions.assertThrows(IllegalArgumentException.class, () -> created.setRecoveryKey(generator.generateKeyPair()), "P-256 pair cannot be encoded");
			}
		}

		@Test
		@DisplayName("recovery key words are compatible with Cryptomator Hub")
		public void testHubRecoveryKey() throws Exception {
			ECKey hub = RecoveryKeyPkcs8Test.hubKeyPair();
			try (UvfUnlockedVault created = UvfUnlockedVault.create(CSPRNG)) {
				created.setRecoveryKey(new KeyPair(hub.toECPublicKey(), hub.toECPrivateKey()));
				Assertions.assertEquals("org.cryptomator.hub.recoverykey." + RecoveryKeyPkcs8Test.HUB_THUMBPRINT, created.recoveryKid());
				Assertions.assertEquals(RecoveryKeyPkcs8Test.HUB_WORDS, created.serializedRecoveryKey());
			}
		}

		@Test
		@DisplayName("custom fields are preserved")
		public void testCustomFields() {
			byte[] config;
			try (UvfVault vault = specVault()) {
				vault.setPassword("secret", CHEAP);
				vault.setRecoveryKey((ECPublicKey) ecKeyPair().getPublic());
				Assertions.assertEquals(42L, vault.customFields().get("org.example.customfield"));
				config = vault.serializeConfig();
			}
			UvfLockedVault locked = (UvfLockedVault) LockedVault.parse(config);
			try (UvfUnlockedVault unlocked = locked.unlock("secret", CSPRNG)) {
				Assertions.assertEquals(42L, unlocked.customFields().get("org.example.customfield"));
				Assertions.assertEquals(473544690, unlocked.initialSeedId());
				Assertions.assertEquals(1075513622, unlocked.latestSeedId());
			}
		}

		@Test
		@DisplayName("serialized config has the structure required by the spec and is readable by nimbus")
		public void testSerializedStructure() throws Exception {
			KeyPair recoveryKey = ecKeyPair();
			byte[] config;
			try (UvfVault vault = specVault()) {
				vault.setPassword("secret", CHEAP);
				vault.setRecoveryKey((ECPublicKey) recoveryKey.getPublic());
				config = vault.serializeConfig();
			}
			JWEObjectJSON jwe = JWEObjectJSON.parse(new String(config, StandardCharsets.UTF_8));
			Assertions.assertEquals("A256GCM", jwe.getHeader().getEncryptionMethod().getName());
			Assertions.assertEquals("json", jwe.getHeader().getContentType());
			Assertions.assertNull(jwe.getHeader().getAlgorithm());
			Assertions.assertNull(jwe.getHeader().getCompressionAlgorithm());
			Assertions.assertEquals(2, jwe.getRecipients().size());
			UnprotectedHeader password = jwe.getRecipients().get(0).getUnprotectedHeader();
			UnprotectedHeader recovery = jwe.getRecipients().get(1).getUnprotectedHeader();
			Assertions.assertEquals("A256KW", password.getParam("alg"));
			Assertions.assertEquals("org.cryptomator.password.argon2", password.getKeyID());
			Assertions.assertEquals(22, ((String) password.getParam("org.cryptomator.password.argon2.salt")).length());
			Assertions.assertEquals(64L, password.getParam("org.cryptomator.password.argon2.memoryKiB"));
			Assertions.assertEquals(1L, password.getParam("org.cryptomator.password.argon2.iterations"));
			Assertions.assertEquals(1L, password.getParam("org.cryptomator.password.argon2.parallelism"));
			Assertions.assertEquals("ECDH-ES+A256KW", recovery.getParam("alg"));
			ECKey embedded = ECKey.parse((Map<String, Object>) recovery.getParam("jwk"));
			Assertions.assertEquals("org.cryptomator.hub.recoverykey." + embedded.computeThumbprint(), recovery.getKeyID());
			Assertions.assertEquals((ECPublicKey) recoveryKey.getPublic(), embedded.toECPublicKey());
			Assertions.assertFalse(embedded.isPrivate());
			Assertions.assertNotNull(recovery.getParam("epk"));
			// nimbus' own multi-recipient decrypter reads it:
			ECKey privateJwk = new ECKey.Builder(embedded).privateKey((ECPrivateKey) recoveryKey.getPrivate()).keyID(recovery.getKeyID()).build();
			jwe.decrypt(new MultiDecrypter(privateJwk, Collections.singleton("uvf.spec.version")));
			Assertions.assertEquals(JsonParser.parseString(UvfSeedsTest.SPEC_PAYLOAD.replace("HDm38i", "HDm38g").replace("QBsJFo", "QBsJFg")), JsonParser.parseString(jwe.getPayload().toString()), "seed ids are serialized canonically");
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
		@DisplayName("garbage, empty recipients and unknown recipients are rejected")
		public void testGarbage() {
			Assertions.assertThrows(VaultConfigLoadException.class, () -> LockedVault.parse("{\"foo\":1}".getBytes(UTF_8)));
			Assertions.assertThrows(VaultConfigLoadException.class, () -> LockedVault.parse("{".getBytes(UTF_8)));
			String json = "{\"protected\":\"" + SPEC_PROTECTED_HEADER + "\",\"iv\":\"AAAAAAAAAAAAAAAA\",\"ciphertext\":\"AAAA\",\"tag\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"recipients\":[{\"header\":{\"alg\":\"PBES2-HS512+A256KW\",\"kid\":\"org.cryptomator.password\",\"p2s\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"p2c\":1000},\"encrypted_key\":\"AAAA\"}]}";
			UvfLockedVault unknown = (UvfLockedVault) LockedVault.parse(json.getBytes(UTF_8));
			Assertions.assertNull(unknown.keyEncryptionKid());
			Assertions.assertNull(unknown.recoveryKid());
			Assertions.assertThrows(VaultConfigLoadException.class, () -> unknown.unlock("secret", CSPRNG));
			Assertions.assertThrows(VaultConfigLoadException.class, () -> unknown.unlock(new SecretKeySpec(new byte[32], "AES"), CSPRNG));
			Assertions.assertThrows(VaultConfigLoadException.class, () -> unknown.recover((ECPrivateKey) ecKeyPair().getPrivate(), CSPRNG));
		}

		@Test
		@DisplayName("tampered recipient headers are rejected")
		public void testTamperedHeaders() {
			KeyPair recoveryKey = ecKeyPair();
			byte[] config;
			try (UvfUnlockedVault created = UvfUnlockedVault.create(CSPRNG)) {
				created.setPassword("secret", CHEAP);
				created.setRecoveryKey((ECPublicKey) recoveryKey.getPublic());
				config = created.serializeConfig();
			}
			Assertions.assertThrows(VaultConfigLoadException.class, () -> tampered(config, 0, h -> h.remove("org.cryptomator.password.argon2.salt")).unlock("secret", CSPRNG));
			Assertions.assertThrows(VaultConfigLoadException.class, () -> tampered(config, 0, h -> h.addProperty("org.cryptomator.password.argon2.memoryKiB", Argon2Params.MAX_MEMORY_KIB + 1L)).unlock("secret", CSPRNG));
			Assertions.assertThrows(VaultConfigLoadException.class, () -> tampered(config, 0, h -> h.addProperty("org.cryptomator.password.argon2.parallelism", "1")).unlock("secret", CSPRNG));
			Assertions.assertThrows(VaultKeyInvalidException.class, () -> tampered(config, 0, h -> h.addProperty("org.cryptomator.password.argon2.iterations", 2)).unlock("secret", CSPRNG), "different cost: different key");
			Assertions.assertThrows(VaultConfigLoadException.class, () -> tampered(config, 1, h -> h.remove("jwk")).recover((ECPrivateKey) recoveryKey.getPrivate(), CSPRNG));
			Assertions.assertThrows(VaultConfigLoadException.class, () -> tampered(config, 1, h -> h.remove("jwk")).unlock("secret", CSPRNG), "the password unlock needs the recovery key to re-encrypt");
			Assertions.assertThrows(VaultConfigLoadException.class, () -> tampered(config, 1, h -> h.addProperty("jwk", "garbage")).recover((ECPrivateKey) recoveryKey.getPrivate(), CSPRNG));
			Assertions.assertThrows(VaultKeyInvalidException.class, () -> tampered(config, 1, h -> h.remove("epk")).recover((ECPrivateKey) recoveryKey.getPrivate(), CSPRNG));
		}

		// modifies the (unprotected, thus unauthenticated) header of one recipient entry
		private UvfLockedVault tampered(byte[] config, int recipient, java.util.function.Consumer<com.google.gson.JsonObject> modification) {
			com.google.gson.JsonObject jwe = JsonParser.parseString(new String(config, UTF_8)).getAsJsonObject();
			modification.accept(jwe.getAsJsonArray("recipients").get(recipient).getAsJsonObject().getAsJsonObject("header"));
			return (UvfLockedVault) LockedVault.parse(jwe.toString().getBytes(UTF_8));
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
