package org.cryptomator.cryptolib.cvf8;

import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.CipherCombo;
import org.cryptomator.cryptolib.api.Cvf8LockedVault;
import org.cryptomator.cryptolib.api.Cvf8UnlockedVault;
import org.cryptomator.cryptolib.api.CvfMasterkey;
import org.cryptomator.cryptolib.api.LockedVault;
import org.cryptomator.cryptolib.api.MasterkeyLoader;
import org.cryptomator.cryptolib.api.UnlockedVault;
import org.cryptomator.cryptolib.api.UnsupportedVaultFormatException;
import org.cryptomator.cryptolib.api.VaultConfigLoadException;
import org.cryptomator.cryptolib.api.VaultDirectory;
import org.cryptomator.cryptolib.api.VaultFile;
import org.cryptomator.cryptolib.api.VaultKeyInvalidException;
import org.cryptomator.cryptolib.api.VaultNode;
import org.cryptomator.cryptolib.api.VaultReader;
import org.cryptomator.cryptolib.api.VaultWriter;
import org.cryptomator.cryptolib.common.SecureRandomMock;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.file.NoSuchFileException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;

class Cvf8VaultTest {

	private static final SecureRandom CSPRNG = SecureRandomMock.PRNG_RANDOM;
	private static final CvfMasterkey ZERO_KEY = new CvfMasterkey(new byte[64]);

	private static Cvf8Vault vault(CipherCombo combo, SecureRandom random) {
		Cvf8ContentCodec codec = combo == CipherCombo.SIV_CTRMAC ? new CtrMacCodec(ZERO_KEY, random) : new GcmCodec(ZERO_KEY, random);
		return new Cvf8Vault(ZERO_KEY.copy(), "vault-id", URI.create("masterkeyfile:masterkey.cryptomator"), combo, 220, codec);
	}

	@Nested
	@DisplayName("config")
	class Config {

		@Test
		@DisplayName("create, serialize, parse and unlock")
		void testCreateAndUnlock() {
			byte[] config;
			try (Cvf8UnlockedVault created = Cvf8UnlockedVault.create(ZERO_KEY, 220, CSPRNG)) {
				Assertions.assertEquals(CipherCombo.SIV_GCM, created.cipherCombo());
				Assertions.assertEquals(URI.create("masterkeyfile:masterkey.cryptomator"), created.keyId());
				Assertions.assertEquals(220, created.shorteningThreshold());
				Assertions.assertEquals("vault.cryptomator", created.configFileName());
				config = created.serializeConfig();
			}
			Assertions.assertFalse(ZERO_KEY.isDestroyed(), "vault must hold its own key copy");

			LockedVault locked = LockedVault.parse(config);
			Cvf8LockedVault cvf8 = Assertions.assertInstanceOf(Cvf8LockedVault.class, locked);
			Assertions.assertEquals(URI.create("masterkeyfile:masterkey.cryptomator"), cvf8.keyId());
			Assertions.assertEquals(8, cvf8.allegedFormatVersion());
			Assertions.assertEquals(220, cvf8.allegedShorteningThreshold());
			Assertions.assertArrayEquals(config, cvf8.encoded());
			try (Cvf8UnlockedVault unlocked = cvf8.unlock(ZERO_KEY, CSPRNG)) {
				Assertions.assertEquals(CipherCombo.SIV_GCM, unlocked.cipherCombo());
				Assertions.assertArrayEquals(ZERO_KEY.getEncoded(), unlocked.masterkey().getEncoded());
			}
		}

		@Test
		@DisplayName("recovery key as words: serialize and recover")
		void testRecoveryKeyWords() {
			byte[] config;
			String words;
			try (Cvf8UnlockedVault created = Cvf8UnlockedVault.create(ZERO_KEY, 220, CSPRNG)) {
				config = created.serializeConfig();
				words = created.serializedRecoveryKey();
			}
			Assertions.assertEquals(44, words.split(" ").length);
			Assertions.assertEquals("ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad", words.substring(0, words.lastIndexOf(' ', words.lastIndexOf(' ') - 1)), "64 zero bytes");

			Cvf8LockedVault locked = (Cvf8LockedVault) LockedVault.parse(config);
			try (Cvf8UnlockedVault recovered = locked.recover(words, CSPRNG)) {
				Assertions.assertArrayEquals(ZERO_KEY.getEncoded(), recovered.masterkey().getEncoded());
				Assertions.assertEquals(words, recovered.serializedRecoveryKey());
			}
			try (UnlockedVault recovered = ((LockedVault) locked).recover(words, CSPRNG)) {
				Assertions.assertInstanceOf(Cvf8UnlockedVault.class, recovered);
			}
			String otherWords;
			try (CvfMasterkey other = CvfMasterkey.generate(CSPRNG); Cvf8UnlockedVault vault = Cvf8UnlockedVault.create(other, 220, CSPRNG)) {
				otherWords = vault.serializedRecoveryKey();
			}
			Assertions.assertThrows(VaultKeyInvalidException.class, () -> locked.recover(otherWords, CSPRNG));
			Assertions.assertThrows(IllegalArgumentException.class, () -> locked.recover("hallo bonjour", CSPRNG));
			Assertions.assertThrows(IllegalArgumentException.class, () -> locked.recover(words + " ad ad", CSPRNG), "46 words: valid checksum impossible, or wrong length");
			Assertions.assertThrows(IllegalArgumentException.class, () -> locked.recover(words.substring(0, words.lastIndexOf(' ')) + " ad", CSPRNG), "checksum mismatch");
		}

		@Test
		@DisplayName("unlock via masterkey loader destroys the loaded key")
		void testUnlockViaLoader() {
			byte[] config = Cvf8UnlockedVault.create(ZERO_KEY, 220, CSPRNG).serializeConfig();
			CvfMasterkey loadedKey = ZERO_KEY.copy();
			MasterkeyLoader loader = Mockito.mock(MasterkeyLoader.class);
			Mockito.doReturn(loadedKey).when(loader).loadKey(URI.create("masterkeyfile:masterkey.cryptomator"));
			Cvf8LockedVault locked = (Cvf8LockedVault) LockedVault.parse(config);
			try (Cvf8UnlockedVault unlocked = locked.unlock(loader, CSPRNG)) {
				Assertions.assertFalse(unlocked.isDestroyed());
			}
			Assertions.assertTrue(loadedKey.isDestroyed());
		}

		@Test
		@DisplayName("unlock with wrong key")
		void testUnlockWithWrongKey() {
			byte[] config = Cvf8UnlockedVault.create(ZERO_KEY, 220, CSPRNG).serializeConfig();
			Cvf8LockedVault locked = (Cvf8LockedVault) LockedVault.parse(config);
			Assertions.assertThrows(VaultKeyInvalidException.class, () -> locked.unlock(CvfMasterkey.generate(CSPRNG), CSPRNG));
		}

		@Test
		@DisplayName("unlock vault of other format version")
		void testUnlockOtherFormatVersion() {
			String token = new String(Cvf8UnlockedVault.create(ZERO_KEY, 220, CSPRNG).serializeConfig(), US_ASCII);
			// re-sign with format 7:
			SignedJWT jwt = Assertions.assertDoesNotThrow(() -> SignedJWT.parse(token));
			JWTClaimsSet claims = Assertions.assertDoesNotThrow(() -> new JWTClaimsSet.Builder(jwt.getJWTClaimsSet()).claim("format", 7).build());
			SignedJWT tampered = new SignedJWT(jwt.getHeader(), claims);
			Assertions.assertDoesNotThrow(() -> tampered.sign(new MACSigner(ZERO_KEY.getEncoded())));
			Cvf8LockedVault locked = (Cvf8LockedVault) LockedVault.parse(tampered.serialize().getBytes(US_ASCII));
			UnsupportedVaultFormatException e = Assertions.assertThrows(UnsupportedVaultFormatException.class, () -> locked.unlock(ZERO_KEY, CSPRNG));
			Assertions.assertEquals(7, e.getDetectedVersion());
			Assertions.assertEquals(8, e.getSupportedVersion());
		}

		@Test
		@DisplayName("parse garbage")
		void testParseGarbage() {
			Assertions.assertThrows(VaultConfigLoadException.class, () -> LockedVault.parse("garbage".getBytes(UTF_8)));
			Assertions.assertThrows(VaultConfigLoadException.class, () -> LockedVault.parse(new byte[0]));
		}

		@Test
		@DisplayName("invalid shortening threshold")
		void testInvalidThreshold() {
			Assertions.assertThrows(IllegalArgumentException.class, () -> Cvf8UnlockedVault.create(ZERO_KEY, 0, CSPRNG));
		}

	}

	@Nested
	@DisplayName("files")
	class Files {

		@Test
		@DisplayName("SIV_CTRMAC: encrypt file 'hello world' with all-zero nonces")
		void testEncryptFileCtrMac() {
			byte[] expected = Base64.getDecoder().decode("AAAAAAAAAAAAAAAAAAAAACNqP4ddv3Z2rUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga24VjC86+zlHN49BfM" //
					+ "dzvHF3f9EE0LSnRLSsu6ps3IRcJgAAAAAAAAAAAAAAAAAAAAC08KwUzWD+5t8kxipYZGvVj719S6Z+RGH1cZcl9SEoEV7XUZ4rzO6+hdzo");
			try (Cvf8Vault vault = vault(CipherCombo.SIV_CTRMAC, SecureRandomMock.NULL_RANDOM)) {
				Assertions.assertArrayEquals(expected, vault.encryptFile("hello world".getBytes(US_ASCII)));
			}
		}

		@Test
		@DisplayName("SIV_CTRMAC: decrypt file 'hello world'")
		void testDecryptFileCtrMac() {
			byte[] ciphertext = Base64.getDecoder().decode("AAAAAAAAAAAAAAAAAAAAANyVwHiiQImCrUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga27XjlTjFxC1VCqZa+" //
					+ "L2eH+xWVgrSLX+JkG35ZJxk5xXswAAAAAAAAAAAAAAAAAAAAC08KwUzWD+5t8kxipYZGvVj719S6Z+RGH1cZcl9SEoEV7XUZ4rzO6+hdzo");
			try (Cvf8Vault vault = vault(CipherCombo.SIV_CTRMAC, SecureRandomMock.NULL_RANDOM)) {
				Assertions.assertArrayEquals("hello world".getBytes(US_ASCII), vault.decryptFile(ciphertext));
			}
		}

		@Test
		@DisplayName("SIV_GCM: encrypt file 'hello world' with nonces 0x55, content key 0x77")
		void testEncryptFileGcm() {
			SecureRandom random = Mockito.mock(SecureRandom.class);
			Mockito.doAnswer(invocation -> {
				Arrays.fill((byte[]) invocation.getArgument(0), (byte) 0x55);
				return null;
			}).doAnswer(invocation -> {
				Arrays.fill((byte[]) invocation.getArgument(0), (byte) 0x77);
				return null;
			}).doAnswer(invocation -> {
				Arrays.fill((byte[]) invocation.getArgument(0), (byte) 0x55);
				return null;
			}).when(random).nextBytes(Mockito.any());
			byte[] expected = Base64.getDecoder().decode("VVVVVVVVVVVVVVVVC+/OFHHE8UvKYTOPlrMO5rCRLAI7/zk8Hjoisja03+yi9ugeeMz1evZhxDExrawl93vf9DKQPx5VVVVVVVVVVVVVVVVSxe6Nf7RO8orsVTzHAmXlNSy1oJpDrg9coV0=");
			try (Cvf8Vault vault = vault(CipherCombo.SIV_GCM, random)) {
				Assertions.assertArrayEquals(expected, vault.encryptFile("hello world".getBytes(US_ASCII)));
			}
		}

		@Test
		@DisplayName("SIV_GCM: decrypt file 'hello world'")
		void testDecryptFileGcm() {
			byte[] ciphertext = Base64.getDecoder().decode("VVVVVVVVVVVVVVVVC+/OFHHE8UvKYTOPlrMO5rCRLAI7/zk8Hjoisja03+yi9ugeeMz1evZhxDExrawl93vf9DKQPx5VVVVVVVVVVVVVVVVSxe6Nf7RO8orsVTzHAmXlNSy1oJpDrg9coV0=");
			try (Cvf8Vault vault = vault(CipherCombo.SIV_GCM, SecureRandomMock.NULL_RANDOM)) {
				Assertions.assertArrayEquals("hello world".getBytes(US_ASCII), vault.decryptFile(ciphertext));
			}
		}

		@ParameterizedTest(name = "{0}: empty file is header only")
		@EnumSource(CipherCombo.class)
		void testEmptyFile(CipherCombo combo) {
			try (Cvf8Vault vault = vault(combo, CSPRNG)) {
				byte[] ciphertext = vault.encryptFile(new byte[0]);
				Assertions.assertEquals(vault.headerSize(), ciphertext.length);
				Assertions.assertArrayEquals(new byte[0], vault.decryptFile(ciphertext));
			}
		}

		@ParameterizedTest(name = "{0}: round trip of {1} bytes via encryptFile/decryptFile, channels and streams")
		@CsvSource({"SIV_CTRMAC,1", "SIV_CTRMAC,32768", "SIV_CTRMAC,32769", "SIV_CTRMAC,100000", "SIV_GCM,1", "SIV_GCM,32768", "SIV_GCM,32769", "SIV_GCM,100000"})
		void testRoundTrip(CipherCombo combo, int size) throws IOException {
			byte[] cleartext = new byte[size];
			new Random(size).nextBytes(cleartext);
			try (Cvf8Vault vault = vault(combo, CSPRNG)) {
				byte[] ciphertext = vault.encryptFile(cleartext);
				Assertions.assertEquals(vault.ciphertextSize(size), ciphertext.length);
				Assertions.assertEquals(size, vault.cleartextSize(ciphertext.length));
				Assertions.assertArrayEquals(cleartext, vault.decryptFile(ciphertext));

				// writable channel:
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				try (WritableByteChannel ch = vault.encryptingChannel(Channels.newChannel(baos))) {
					ch.write(ByteBuffer.wrap(cleartext));
				}
				Assertions.assertEquals(ciphertext.length, baos.size());
				Assertions.assertArrayEquals(cleartext, vault.decryptFile(baos.toByteArray()));

				// pull-style encrypting channel:
				ByteBuffer pulled = ByteBuffer.allocate(ciphertext.length + 1);
				try (ReadableByteChannel ch = vault.encryptingChannel(Channels.newChannel(new ByteArrayInputStream(cleartext)))) {
					Assertions.assertEquals(ciphertext.length, ch.read(pulled));
					Assertions.assertEquals(-1, ch.read(pulled));
				}
				pulled.flip();
				Assertions.assertArrayEquals(cleartext, vault.decryptFile(Arrays.copyOf(pulled.array(), pulled.remaining())));

				// readable channel:
				ByteBuffer decrypted = ByteBuffer.allocate(size + 1);
				try (ReadableByteChannel ch = vault.decryptingChannel(Channels.newChannel(new ByteArrayInputStream(ciphertext)))) {
					Assertions.assertEquals(size, ch.read(decrypted));
					Assertions.assertEquals(-1, ch.read(decrypted));
				}
				Assertions.assertArrayEquals(cleartext, Arrays.copyOf(decrypted.array(), size));

				// streams:
				ByteArrayOutputStream encryptedViaStream = new ByteArrayOutputStream();
				try (OutputStream out = vault.encryptingStream(encryptedViaStream)) {
					out.write(cleartext);
				}
				ByteArrayOutputStream decryptedViaStream = new ByteArrayOutputStream();
				try (InputStream in = vault.decryptingStream(new ByteArrayInputStream(encryptedViaStream.toByteArray()))) {
					byte[] buf = new byte[1000];
					int n;
					while ((n = in.read(buf)) != -1) {
						decryptedViaStream.write(buf, 0, n);
					}
				}
				Assertions.assertArrayEquals(cleartext, decryptedViaStream.toByteArray());
			}
		}

		@ParameterizedTest(name = "{0}: manipulated chunk is detected")
		@EnumSource(CipherCombo.class)
		void testManipulatedChunk(CipherCombo combo) {
			try (Cvf8Vault vault = vault(combo, CSPRNG)) {
				byte[] ciphertext = vault.encryptFile(new byte[50000]);
				ciphertext[vault.headerSize() + 20] ^= 0x01;
				Assertions.assertThrows(AuthenticationFailedException.class, () -> vault.decryptFile(ciphertext));
				ByteBuffer dst = ByteBuffer.allocate(50000);
				Assertions.assertThrows(AuthenticationFailedException.class, () -> {
					try (ReadableByteChannel ch = vault.decryptingChannel(Channels.newChannel(new ByteArrayInputStream(ciphertext)))) {
						ch.read(dst);
					}
				});
			}
		}

		@ParameterizedTest(name = "{0}: manipulated header is detected")
		@EnumSource(CipherCombo.class)
		void testManipulatedHeader(CipherCombo combo) {
			try (Cvf8Vault vault = vault(combo, CSPRNG)) {
				byte[] ciphertext = vault.encryptFile(new byte[100]);
				ciphertext[vault.headerSize() - 1] ^= 0x01;
				Assertions.assertThrows(AuthenticationFailedException.class, () -> vault.decryptFile(ciphertext));
				Assertions.assertThrows(AuthenticationFailedException.class, () -> vault.openFile(ByteBuffer.wrap(ciphertext, 0, vault.headerSize()), ciphertext.length));
			}
		}

		@ParameterizedTest(name = "{0}: truncated file is detected")
		@EnumSource(CipherCombo.class)
		void testTruncatedFile(CipherCombo combo) {
			try (Cvf8Vault vault = vault(combo, CSPRNG)) {
				byte[] ciphertext = vault.encryptFile(new byte[100]);
				byte[] truncated = Arrays.copyOf(ciphertext, vault.headerSize() + 10);
				Assertions.assertThrows(IllegalArgumentException.class, () -> vault.decryptFile(truncated));
				Assertions.assertThrows(IllegalArgumentException.class, () -> vault.openFile(ByteBuffer.wrap(truncated, 0, vault.headerSize()), truncated.length));
			}
		}

		@ParameterizedTest(name = "{0}: openFile derives size and header is stable")
		@EnumSource(CipherCombo.class)
		void testOpenFile(CipherCombo combo) {
			try (Cvf8Vault vault = vault(combo, CSPRNG)) {
				byte[] ciphertext = vault.encryptFile(new byte[40000]);
				try (VaultFile file = vault.openFile(ByteBuffer.wrap(ciphertext, 0, vault.headerSize()), ciphertext.length)) {
					Assertions.assertEquals(40000, file.size());
					Assertions.assertEquals(0, file.seedId());
					Assertions.assertArrayEquals(Arrays.copyOf(ciphertext, vault.headerSize()), toArray(file.encryptedHeader()));
					Assertions.assertArrayEquals(Arrays.copyOf(ciphertext, vault.headerSize()), toArray(file.encryptedHeader()));
					Assertions.assertEquals(2, file.chunkCount(40000));
					Assertions.assertEquals(1, file.chunkIndex(32768));
					Assertions.assertEquals(vault.headerSize() + vault.ciphertextChunkSize(), file.ciphertextChunkOffset(1));
				}
			}
		}

		@ParameterizedTest(name = "{0}: symlink target round trip")
		@EnumSource(CipherCombo.class)
		void testSymlink(CipherCombo combo) {
			try (Cvf8Vault vault = vault(combo, CSPRNG)) {
				byte[] encrypted = vault.encryptSymlinkTarget("../tärget/file.txt");
				Assertions.assertEquals("../tärget/file.txt", vault.decryptSymlinkTarget(encrypted));
			}
		}

	}

	@Nested
	@DisplayName("directories and nodes")
	class Directories {

		private final Map<String, byte[]> files = new HashMap<>();
		private final VaultWriter writer = files::put;
		private final VaultReader reader = path -> {
			byte[] result = files.get(path);
			if (result == null) {
				throw new NoSuchFileException(path);
			}
			return result;
		};
		private Cvf8Vault vault;

		@BeforeEach
		void setup() {
			vault = vault(CipherCombo.SIV_GCM, CSPRNG);
		}

		@Test
		@DisplayName("root directory")
		void testRootDirectory() {
			VaultDirectory root = vault.rootDirectory();
			Assertions.assertArrayEquals(new byte[0], root.dirId());
			Assertions.assertEquals(32, root.dirHash().length());
			Assertions.assertEquals("d/" + root.dirHash().substring(0, 2) + "/" + root.dirHash().substring(2), root.dirPath());
			Assertions.assertEquals(root.dirPath() + "/dirid.c9r", root.backupFilePath());
			Assertions.assertEquals(root, vault.rootDirectory());
			Assertions.assertEquals(root.hashCode(), vault.rootDirectory().hashCode());
		}

		@Test
		@DisplayName("dir.c9r contains the plaintext id, dirid.c9r the encrypted id")
		void testDirectoryMetadata() throws IOException {
			VaultDirectory dir = vault.newDirectory();
			Assertions.assertEquals(36, dir.dirId().length);
			Assertions.assertArrayEquals(dir.dirId(), dir.encryptedMetadata());
			Assertions.assertEquals(dir, vault.directory(dir.encryptedMetadata()));
			Assertions.assertEquals(dir, vault.directoryFromBackup(dir.encryptedMetadataBackup()));
			Assertions.assertNotEquals(dir, vault.newDirectory());

			dir.writeMetadataBackup(writer);
			Assertions.assertEquals(dir, vault.directoryFromBackup(files.get(dir.backupFilePath())));
		}

		@Test
		@DisplayName("invalid dir.c9r contents")
		void testInvalidDirectoryMetadata() {
			Assertions.assertThrows(IllegalArgumentException.class, () -> vault.directory(new byte[0]));
			Assertions.assertThrows(IllegalArgumentException.class, () -> vault.directory(new byte[1001]));
		}

		@Test
		@DisplayName("name encryption is deterministic and bound to the directory")
		void testNames() throws IOException {
			VaultDirectory dir = vault.newDirectory();
			VaultNode node = dir.encryptName("Documents");
			Assertions.assertEquals(node.name(), dir.encryptName("Documents").name());
			Assertions.assertTrue(node.name().endsWith(".c9r"));
			Assertions.assertFalse(node.isShortened());
			Assertions.assertEquals(node.name(), node.inflated());
			Assertions.assertEquals(node.name(), node.contentsFile());
			Assertions.assertEquals(node.name() + "/dir.c9r", node.dirFile());
			Assertions.assertEquals(node.name() + "/symlink.c9r", node.symlinkFile());
			Assertions.assertThrows(IllegalStateException.class, node::inflatedNameFile);

			Assertions.assertEquals("Documents", dir.decryptName(node.name()));
			Assertions.assertEquals("Documents", dir.decryptName(node.name(), reader));
			Assertions.assertThrows(AuthenticationFailedException.class, () -> vault.newDirectory().decryptName(node.name()));
			Assertions.assertThrows(IllegalArgumentException.class, () -> dir.decryptName("masterkey.cryptomator"));
			Assertions.assertThrows(AuthenticationFailedException.class, () -> dir.decryptName("dirid.c9r")); // ends with .c9r but isn't a ciphertext name
			Assertions.assertThrows(AuthenticationFailedException.class, () -> dir.decryptName("lol.c9r"));
		}

		@ParameterizedTest(name = "decrypted name {0} is rejected")
		@ValueSource(strings = {"", ".", "..", "a/b", "a\u0000b"})
		void testInvalidCleartextNames(String name) {
			VaultDirectory dir = vault.newDirectory();
			VaultNode node = dir.encryptName(name);
			Assertions.assertThrows(AuthenticationFailedException.class, () -> dir.decryptName(node.name()));
		}

		@Test
		@DisplayName("name shortening at threshold")
		void testShortening() throws IOException {
			VaultDirectory dir = vault.rootDirectory();
			// 146 cleartext chars -> 146 + 16 = 162 bytes -> 216 base64 chars + 4 = 220 chars: not shortened
			VaultNode atThreshold = dir.encryptName(repeat('a', 146));
			Assertions.assertEquals(220, atThreshold.inflated().length());
			Assertions.assertFalse(atThreshold.isShortened());
			// 147 chars -> 163 bytes -> 220 base64 chars (padded) + 4 = 224 chars: shortened
			VaultNode shortened = dir.encryptName(repeat('a', 147));
			Assertions.assertEquals(224, shortened.inflated().length());
			Assertions.assertTrue(shortened.isShortened());
			Assertions.assertTrue(shortened.name().endsWith(".c9s"));
			Assertions.assertEquals(vault.shortenName(shortened.inflated()), shortened.name());
			Assertions.assertTrue(vault.isShortenedName(shortened.name()));
			Assertions.assertEquals(shortened.name() + "/contents.c9r", shortened.contentsFile());
			Assertions.assertEquals(shortened.name() + "/name.c9s", shortened.inflatedNameFile());
			Assertions.assertEquals(146, vault.maxCleartextNameLength(255));
			Assertions.assertEquals(146, vault.maxCleartextNameLength(220));
			Assertions.assertEquals(80, vault.maxCleartextNameLength(132));

			// listing: inflate via reader
			Assertions.assertThrows(IllegalArgumentException.class, () -> dir.decryptName(shortened.name()));
			files.put(dir.dirPath() + "/" + shortened.inflatedNameFile(), shortened.inflated().getBytes(UTF_8));
			Assertions.assertEquals(repeat('a', 147), dir.decryptName(shortened.name(), reader));
		}

		@Test
		@DisplayName("shortened name is base64url(sha1(inflated)) + .c9s")
		void testShortenName() {
			// printf 'foo.c9r' | openssl dgst -sha1 -binary | base64 | tr '+/' '-_'
			Assertions.assertEquals("XzXY10UamRa7Fdaj94oXgEWr_tM=.c9s", vault.shortenName("foo.c9r"));
		}

		@Test
		@DisplayName("create and resolve subdirectory via callbacks")
		void testCreateDirectory() throws IOException {
			VaultDirectory parent = vault.rootDirectory();
			VaultDirectory child = vault.newDirectory();
			VaultNode node = parent.encryptName("sub");
			node.createDirectory(child, writer);
			Assertions.assertEquals(2, files.size());
			Assertions.assertArrayEquals(child.dirId(), files.get(parent.dirPath() + "/" + node.dirFile()));
			Assertions.assertTrue(files.containsKey(child.backupFilePath()));

			Assertions.assertEquals(child, node.directory(reader));
			Assertions.assertEquals(child, node.directory(files.get(parent.dirPath() + "/" + node.dirFile())));
			Assertions.assertEquals("sub", parent.decryptName(node.name(), reader));
		}

		@Test
		@DisplayName("create shortened subdirectory writes name.c9s")
		void testCreateShortenedDirectory() throws IOException {
			VaultDirectory parent = vault.rootDirectory();
			VaultNode node = parent.encryptName(repeat('b', 200));
			node.createDirectory(vault.newDirectory(), writer);
			Assertions.assertEquals(3, files.size());
			Assertions.assertArrayEquals(node.inflated().getBytes(UTF_8), files.get(parent.dirPath() + "/" + node.inflatedNameFile()));
			Assertions.assertEquals(repeat('b', 200), parent.decryptName(node.name(), reader));
		}

		@Test
		@DisplayName("create and resolve symlink via callbacks")
		void testCreateSymlink() throws IOException {
			VaultDirectory parent = vault.rootDirectory();
			VaultNode node = parent.encryptName("link");
			node.createSymlink("/etc/passwd", writer);
			Assertions.assertEquals(1, files.size());
			Assertions.assertEquals("/etc/passwd", node.symlinkTarget(reader));
			Assertions.assertEquals("/etc/passwd", vault.decryptSymlinkTarget(files.get(parent.dirPath() + "/" + node.symlinkFile())));
		}

		@Test
		@DisplayName("directory hashes match cryptolib 2.x")
		void testDirHashVectors() {
			// produced by cryptolib 2.x FileNameCryptor.hashDirectoryId with an all-zero masterkey
			Assertions.assertEquals("KG6TFDGKXGZEGWRZOGTDFDF4YEGAZO6Q", vault.rootDirectory().dirHash());
			Assertions.assertEquals("d/KG/6TFDGKXGZEGWRZOGTDFDF4YEGAZO6Q", vault.rootDirectory().dirPath());
			Assertions.assertEquals("MS356E7ZZNDLOWOP7PZEPC7QETRZKA3K", vault.directory("abc".getBytes(UTF_8)).dirHash());
		}

	}

	@ParameterizedTest(name = "destroying the vault destroys the key ({0})")
	@ValueSource(strings = {"SIV_CTRMAC", "SIV_GCM"})
	void testDestroy(String combo) {
		Cvf8Vault vault = vault(CipherCombo.valueOf(combo), CSPRNG);
		Assertions.assertFalse(vault.isDestroyed());
		vault.close();
		Assertions.assertTrue(vault.isDestroyed());
		Assertions.assertTrue(vault.masterkey().isDestroyed());
		Assertions.assertThrows(IllegalStateException.class, vault::createFile);
		Assertions.assertThrows(IllegalStateException.class, vault::rootDirectory);
	}

	private static String repeat(char c, int n) {
		char[] chars = new char[n];
		Arrays.fill(chars, c);
		return new String(chars);
	}

	private static byte[] toArray(ByteBuffer buf) {
		byte[] result = new byte[buf.remaining()];
		buf.get(result);
		return result;
	}

}
