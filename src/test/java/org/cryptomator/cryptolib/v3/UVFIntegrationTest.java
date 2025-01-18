package org.cryptomator.cryptolib.v3;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.UVFMasterkey;
import org.cryptomator.cryptolib.common.DecryptingReadableByteChannel;
import org.cryptomator.cryptolib.common.EncryptingWritableByteChannel;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.charset.StandardCharsets;
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
				"        \"HDm38g\": \"ypeBEsobvcr6wjGzmiPcTaeG7/gUfE5yuYB3ha/uSLs=\",\n" +
				"        \"gBryKw\": \"PiPoFgA5WUoziU9lZOGxNIu9egCI1CxKy3PurtWcAJ0=\",\n" +
				"        \"QBsJFg\": \"Ln0sA6lQeuJl7PW1NWiFpTOTogKdJBOUmXJloaJa78Y=\"\n" +
				"    },\n" +
				"    \"initialSeed\": \"HDm38i\",\n" +
				"    \"latestSeed\": \"QBsJFo\",\n" +
				"    \"kdf\": \"HKDF-SHA512\",\n" +
				"    \"kdfSalt\": \"NIlr89R7FhochyP4yuXZmDqCnQ0dBB3UZ2D+6oiIjr8=\",\n" +
				"    \"org.example.customfield\": 42\n" +
				"}";
		masterkey = UVFMasterkey.fromDecryptedPayload(json);
		cryptor = CryptorProvider.forScheme(CryptorProvider.Scheme.UVF_DRAFT).provide(masterkey, CSPRNG);
	}

	@Test
	public void testRootDirId() {
		byte[] rootDirId = masterkey.rootDirId();
		Assertions.assertEquals("5WEGzwKkAHPwVSjT2Brr3P3zLz7oMiNpMn/qBvht7eM=", Base64.getEncoder().encodeToString(rootDirId));
	}

	@Test
	public void testRootDirHash() {
		byte[] rootDirId = Base64.getDecoder().decode("5WEGzwKkAHPwVSjT2Brr3P3zLz7oMiNpMn/qBvht7eM=");
		String dirHash = cryptor.fileNameCryptor(masterkey.firstRevision()).hashDirectoryId(rootDirId);
		Assertions.assertEquals("RKHZLENL3PQIW6GZHE3KRRRGLFBHWHRU", dirHash);
	}

	@Test
	public void testContentEncryption() throws IOException {
		ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
		try (EncryptingWritableByteChannel ch = new EncryptingWritableByteChannel(Channels.newChannel(baos), cryptor)) {
			int written = ch.write(StandardCharsets.UTF_8.encode("Hello, World!"));
			Assertions.assertEquals(13, written);
		}
		byte[] result = baos.toByteArray();
		Assertions.assertArrayEquals(new byte[]{0x75, 0x76, 0x66, 0x00}, Arrays.copyOf(result, 4));
		Assertions.assertArrayEquals(Base64.getUrlDecoder().decode("QBsJFo"), Arrays.copyOfRange(result, 4, 8));
	}

	@Test
	public void testContentDecryption() throws IOException {
		byte[] input = Base64.getDecoder().decode("dXZmAEAbCRZxhI5sPsMiMlAQpwXzsOw13pBVX/yHydeHoOlHBS9d+wVpmRvzUKx5HQUmtGR4avjDownMNOS4sBX8G0SVc5dIADKnGUOwgF20kkc/EpGzrrgkS3C9lZoRPPOj3dm2ONfy3UkT1Q==");
		ByteBuffer result = ByteBuffer.allocate(100);
		try (DecryptingReadableByteChannel ch = new DecryptingReadableByteChannel(Channels.newChannel(new ByteArrayInputStream(input)), cryptor, true)) {
			int read = ch.read(result);
			Assertions.assertEquals(13, read);
		}
		result.flip();
		Assertions.assertEquals("Hello, World!", StandardCharsets.UTF_8.decode(result).toString());
	}

}
