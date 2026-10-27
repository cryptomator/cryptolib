package org.cryptomator.cryptolib.v3;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.DirectoryContentCryptor;
import org.cryptomator.cryptolib.api.DirectoryMetadata;
import org.cryptomator.cryptolib.api.UVFMasterkey;
import org.cryptomator.cryptolib.common.DecryptingReadableByteChannel;
import org.cryptomator.cryptolib.common.EncryptingWritableByteChannel;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class UVFIntegrationTest {

	private static final SecureRandom CSPRNG = new SecureRandom();
	private static UVFMasterkey masterkey;
	private static Cryptor cryptor;

	@BeforeAll
	public static void setUp() {
		// example payload from the UVF spec, see UVFMasterkeyTest:
		String json = "{\n" +
				"    \"fileFormat\": \"AES-256-GCM-32k\",\n" +
				"    \"nameFormat\": \"AES-SIV-512-B64URL\",\n" +
				"    \"seeds\": {\n" +
				"        \"DU3kfQ\": \"ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs\",\n" +
				"        \"YuRlmw\": \"PiPoFgA5WUoziU9lZOGxNIu9egCI1CxKy3PurtWcAJ0\",\n" +
				"        \"q8ZMqw\": \"Ln0sA6lQeuJl7PW1NWiFpTOTogKdJBOUmXJloaJa78Y\"\n" +
				"    },\n" +
				"    \"initialSeed\": \"DU3kfQ\",\n" +
				"    \"latestSeed\": \"q8ZMqw\",\n" +
				"    \"kdf\": \"HKDF-SHA512\",\n" +
				"    \"kdfSalt\": \"NIlr89R7FhochyP4yuXZmDqCnQ0dBB3UZ2D-6oiIjr8\",\n" +
				"    \"org.example.customfield\": 42\n" +
				"}";
		masterkey = UVFMasterkey.fromDecryptedPayload(json);
		cryptor = CryptorProvider.forScheme(CryptorProvider.Scheme.UVF_DRAFT).provide(masterkey, CSPRNG);
	}

	@Test
	@DisplayName("root dir id must be deterministic")
	public void testRootDirId() {
		byte[] rootDirId = masterkey.rootDirId();
		Assertions.assertEquals("5WEGzwKkAHPwVSjT2Brr3P3zLz7oMiNpMn/qBvht7eM=", Base64.getEncoder().encodeToString(rootDirId));
	}

	@Test
	@DisplayName("root dir hash must be deterministic")
	public void testRootDirHash() {
		byte[] rootDirId = Base64.getDecoder().decode("5WEGzwKkAHPwVSjT2Brr3P3zLz7oMiNpMn/qBvht7eM=");
		String dirHash = cryptor.fileNameCryptor(masterkey.firstRevision()).hashDirectoryId(rootDirId);
		Assertions.assertEquals("RZK7ZH7KBXULNEKBMGX3CU42PGUIAIX4", dirHash);
	}

	@Test
	@DisplayName("encrypt dir.uvf for root directory")
	public void testRootDirUvfEncryption() {
		DirectoryMetadata rootDirMetadata = cryptor.directoryContentCryptor().rootDirectoryMetadata();
		byte[] result = cryptor.directoryContentCryptor().encryptDirectoryMetadata(rootDirMetadata);
		Assertions.assertArrayEquals(new byte[]{0x75, 0x76, 0x66, 0x01}, Arrays.copyOf(result, 4), "expected to begin with UVF magic bytes and spec version 1");
		Assertions.assertArrayEquals(Base64.getUrlDecoder().decode("DU3kfQ"), Arrays.copyOfRange(result, 4, 8), "expected seed to be initial seed");
	}

	@Test
	@DisplayName("decrypt dir.uvf for root directory")
	public void testRootDirUvfDecryption() {
		byte[] input = Base64.getDecoder().decode("dXZmAQ1N5H29YIjDh1UAzXRxhQd1DvVThqIWmBy8CFAJ7wOqKnQZCU9LmQ27cmRfzqJ1EWFqkQ0E70rtLN/2oZRQFPHCLK3+oytYu8EW8YLWR1g+0m+P1ql5sDKpJ6Hn49oaALdgAV8llw4+tZ0i5DjzgvTdJsAxprgWe3bgBgc=");
		DirectoryMetadata result = cryptor.directoryContentCryptor().decryptDirectoryMetadata(input);
		DirectoryMetadataImpl metadata = Assertions.assertInstanceOf(DirectoryMetadataImpl.class, result);
		Assertions.assertArrayEquals(masterkey.rootDirId(), metadata.dirId());
		Assertions.assertEquals(masterkey.firstRevision(), metadata.seedId());

	}

	@Test
	@DisplayName("encrypt file containing 'Hello, World!'")
	public void testContentEncryption() throws IOException {
		byte[] result = encryptFile(StandardCharsets.UTF_8.encode("Hello, World!"), cryptor);
		Assertions.assertEquals(68 + 12 + 13 + 16, result.length);
		Assertions.assertArrayEquals(new byte[]{0x75, 0x76, 0x66, 0x01}, Arrays.copyOf(result, 4), "expected to begin with UVF magic bytes and spec version 1");
		Assertions.assertArrayEquals(Base64.getUrlDecoder().decode("q8ZMqw"), Arrays.copyOfRange(result, 4, 8), "expected seed to be latest seed");
	}

	@Test
	@DisplayName("decrypt file containing 'Hello, World!'")
	public void testContentDecryption() throws IOException {
		byte[] input = Base64.getDecoder().decode("dXZmAavGTKvciiONJhtLXnPOlETc1FxtwVskYFdGIbzl4To51AbVX9X60nqcwRoWvSdiwAQsi9hRbImbSdTbbjqqxFeTkKlcThFiaGQDgDS5AFLN9NLf0VvlL9N4r/8G9OoRDhoYuUrdVS1dYg==");
		byte[] result = decryptFile(ByteBuffer.wrap(input), cryptor);
		Assertions.assertEquals(13, result.length);
		Assertions.assertEquals("Hello, World!", new String(result, StandardCharsets.UTF_8));
	}

	@DisplayName("encrypt and decrypt files around chunk boundaries")
	@ParameterizedTest(name = "{0} bytes")
	@ValueSource(ints = {0, 1, 32739, 32740, 32741, 65480, 65481})
	public void testContentRoundTrip(int size) throws IOException {
		byte[] cleartext = new byte[size];
		CSPRNG.nextBytes(cleartext);

		byte[] ciphertext = encryptFile(ByteBuffer.wrap(cleartext), cryptor);
		Assertions.assertEquals(cryptor.fileHeaderCryptor().headerSize() + cryptor.fileContentCryptor().ciphertextSize(size), ciphertext.length);
		byte[] decrypted = decryptFile(ByteBuffer.wrap(ciphertext), cryptor);

		Assertions.assertArrayEquals(cleartext, decrypted);
	}

	@DisplayName("reject files truncated at a chunk boundary (missing EOF chunk)")
	@ParameterizedTest(name = "{0} bytes")
	@ValueSource(ints = {0, 32740, 65480})
	public void testTruncatedEofChunk(int size) throws IOException {
		byte[] ciphertext = encryptFile(ByteBuffer.wrap(new byte[size]), cryptor);
		byte[] truncated = Arrays.copyOf(ciphertext, ciphertext.length - 28);

		Assertions.assertThrows(IllegalArgumentException.class, () -> cryptor.fileContentCryptor().cleartextSize(truncated.length - cryptor.fileHeaderCryptor().headerSize()));
		ByteBuffer result = ByteBuffer.allocate(size + 1);
		try (DecryptingReadableByteChannel ch = new DecryptingReadableByteChannel(Channels.newChannel(new ByteArrayInputStream(truncated)), cryptor, true)) {
			IOException e = Assertions.assertThrows(IOException.class, () -> {
				while (ch.read(result) != -1) {
					// read until EOF
				}
			});
			Assertions.assertEquals("Unauthentic ciphertext", e.getMessage());
		}
	}

	@Test
	@DisplayName("create reference directory structure")
	public void testCreateReferenceDirStructure(@TempDir Path vaultDir) throws IOException {
		DirectoryContentCryptor dirContentCryptor = cryptor.directoryContentCryptor();

		// ROOT
		DirectoryMetadata rootDirMetadata = cryptor.directoryContentCryptor().rootDirectoryMetadata();
		String rootDirPath = dirContentCryptor.dirPath(rootDirMetadata);
		String rootDirUvfFilePath = rootDirPath + "/dir.uvf";
		byte[] rootDirUvfFileContents = dirContentCryptor.encryptDirectoryMetadata(rootDirMetadata);
		Files.createDirectories(vaultDir.resolve(rootDirPath));
		Files.write(vaultDir.resolve(rootDirUvfFilePath), rootDirUvfFileContents);
		DirectoryContentCryptor.Encrypting filesWithinRootDir = dirContentCryptor.fileNameEncryptor(rootDirMetadata);

		// ROOT/foo.txt
		String fooFileName = filesWithinRootDir.encrypt("foo.txt");
		String fooFilePath = rootDirPath + "/" + fooFileName;
		byte[] fooFileContents = encryptFile(StandardCharsets.UTF_8.encode("Hello Foo"), cryptor);
		Files.write(vaultDir.resolve(fooFilePath), fooFileContents);

		// ROOT/subdir
		DirectoryMetadata subDirMetadata = dirContentCryptor.newDirectoryMetadata();
		String subDirName = filesWithinRootDir.encrypt("subdir");
		String subDirUvfFilePath1 = rootDirPath + "/" + subDirName + "/dir.uvf";
		byte[] subDirUvfFileContents1 = dirContentCryptor.encryptDirectoryMetadata(subDirMetadata);
		Files.createDirectories(vaultDir.resolve(rootDirPath + "/" + subDirName));
		Files.write(vaultDir.resolve(subDirUvfFilePath1), subDirUvfFileContents1);
		String subDirPath = dirContentCryptor.dirPath(subDirMetadata);
		String subDirUvfFilePath2 = subDirPath + "/dir.uvf";
		byte[] subDirUvfFileContents2 = dirContentCryptor.encryptDirectoryMetadata(subDirMetadata);
		Files.createDirectories(vaultDir.resolve(subDirPath));
		Files.write(vaultDir.resolve(subDirUvfFilePath2), subDirUvfFileContents2);
		DirectoryContentCryptor.Encrypting filesWithinSubDir = dirContentCryptor.fileNameEncryptor(subDirMetadata);

		// ROOT/subdir/bar.txt
		String barFileName = filesWithinSubDir.encrypt("bar.txt");
		String barFilePath = subDirPath + "/" + barFileName;
		byte[] barFileContents = encryptFile(StandardCharsets.UTF_8.encode("Hello Bar"), cryptor);
		Files.write(vaultDir.resolve(barFilePath), barFileContents);

		// ROOT/link
		String linkName = filesWithinRootDir.encrypt("link");
		String linkUvfFilePath = rootDirPath + "/" + linkName + "/symlink.uvf";
		byte[] linkUvfFileContents = dirContentCryptor.encryptSymlinkTarget("subdir/bar.txt");
		Files.createDirectories(vaultDir.resolve(rootDirPath + "/" + linkName));
		Files.write(vaultDir.resolve(linkUvfFilePath), linkUvfFileContents);

		// set breakpoint here to inspect the created directory structure
		System.out.println(vaultDir);

	}

	private static byte[] encryptFile(ByteBuffer cleartext, Cryptor cryptor) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try (EncryptingWritableByteChannel ch = new EncryptingWritableByteChannel(Channels.newChannel(baos), cryptor)) {
			ch.write(cleartext);
		}
		return baos.toByteArray();
	}

	private static byte[] decryptFile(ByteBuffer ciphertext, Cryptor cryptor) throws IOException {
		assert ciphertext.hasArray();
		byte[] in = ciphertext.array();
		int cleartextSize = (int) cryptor.fileContentCryptor().cleartextSize(in.length - cryptor.fileHeaderCryptor().headerSize());
		ByteBuffer result = ByteBuffer.allocate(cleartextSize + 1); // one spare byte, so that the channel can report EOF
		try (DecryptingReadableByteChannel ch = new DecryptingReadableByteChannel(Channels.newChannel(new ByteArrayInputStream(in)), cryptor, true)) {
			while (ch.read(result) != -1) {
				Assertions.assertTrue(result.hasRemaining(), "decrypted more than the expected " + cleartextSize + " bytes");
			}
		}
		Assertions.assertEquals(cleartextSize, result.position());
		return Arrays.copyOf(result.array(), cleartextSize);
	}

}
