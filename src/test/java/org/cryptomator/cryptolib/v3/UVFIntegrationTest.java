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
		// copied from UVFMasterkeyTest:
		String json = "{\n" +
				"    \"fileFormat\": \"AES-256-GCM-32k\",\n" +
				"    \"nameFormat\": \"AES-SIV-512-B64URL\",\n" +
				"    \"seeds\": {\n" +
				"        \"HDm38g\": \"ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs\",\n" +
				"        \"gBryKw\": \"PiPoFgA5WUoziU9lZOGxNIu9egCI1CxKy3PurtWcAJ0\",\n" +
				"        \"QBsJFg\": \"Ln0sA6lQeuJl7PW1NWiFpTOTogKdJBOUmXJloaJa78Y\"\n" +
				"    },\n" +
				"    \"initialSeed\": \"HDm38i\",\n" +
				"    \"latestSeed\": \"QBsJFo\",\n" +
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
		Assertions.assertArrayEquals(new byte[]{0x75, 0x76, 0x66, 0x00}, Arrays.copyOf(result, 4), "expected to begin with UVF0 magic bytes");
		Assertions.assertArrayEquals(Base64.getUrlDecoder().decode("HDm38i"), Arrays.copyOfRange(result, 4, 8), "expected seed to be initial seed");
	}

	@Test
	@DisplayName("decrypt dir.uvf for root directory")
	public void testRootDirUvfDecryption() {
		byte[] input = Base64.getDecoder().decode("dXZmABw5t/Ievp74RjIgGHn4+/Zt32dmqmYhmHiPNQ5Q2z+WYb4z8NbnynTgMWlGBCc65bTqSt4Pqhj9EGhrn8KVbQqzBVWcZkLVr4tntfvgZoVJYkeD5w9mJMwRlQJwqiC0uR+Lk2aBT2cfdPT92e/6+t7nlvoYtoahMtowCqY=");
		DirectoryMetadata result = cryptor.directoryContentCryptor().decryptDirectoryMetadata(input);
		DirectoryMetadataImpl metadata = Assertions.assertInstanceOf(DirectoryMetadataImpl.class, result);
		Assertions.assertArrayEquals(masterkey.rootDirId(), metadata.dirId());
		Assertions.assertEquals(masterkey.firstRevision(), metadata.seedId());

	}

	@Test
	@DisplayName("encrypt file containing 'Hello, World!'")
	public void testContentEncryption() throws IOException {
		byte[] result = encryptFile(StandardCharsets.UTF_8.encode("Hello, World!"), cryptor);
		Assertions.assertArrayEquals(new byte[]{0x75, 0x76, 0x66, 0x00}, Arrays.copyOf(result, 4), "expected to begin with UVF0 magic bytes");
		Assertions.assertArrayEquals(Base64.getUrlDecoder().decode("QBsJFo"), Arrays.copyOfRange(result, 4, 8), "expected seed to be latest seed");
	}

	@Test
	@DisplayName("decrypt file containing 'Hello, World!'")
	public void testContentDecryption() throws IOException {
		byte[] input = Base64.getDecoder().decode("dXZmAEAbCRZxhI5sPsMiMlAQpwXzsOw13pBVX/yHydeHoOlHBS9d+wVpmRvzUKx5HQUmtGR4avjDownMNOS4sBX8G0SVc5dIADKnGUOwgF20kkc/EpGzrrgkS3C9lZoRPPOj3dm2ONfy3UkT1Q==");
		byte[] result = decryptFile(ByteBuffer.wrap(input), cryptor);
		Assertions.assertEquals(13, result.length);
		Assertions.assertEquals("Hello, World!", new String(result, StandardCharsets.UTF_8));
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
		ByteBuffer result = ByteBuffer.allocate((int) cryptor.fileContentCryptor().cleartextSize(in.length) - cryptor.fileHeaderCryptor().headerSize());
		try (DecryptingReadableByteChannel ch = new DecryptingReadableByteChannel(Channels.newChannel(new ByteArrayInputStream(in)), cryptor, true)) {
			int read = ch.read(result);
			Assertions.assertEquals(13, read);
		}
		return result.array();
	}

}
