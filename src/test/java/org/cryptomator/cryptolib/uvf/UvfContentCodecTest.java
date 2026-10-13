package org.cryptomator.cryptolib.uvf;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.common.CipherSupplier;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;
import org.cryptomator.cryptolib.common.GcmTestHelper;
import org.cryptomator.cryptolib.common.ObjectPool;
import org.cryptomator.cryptolib.common.SecureRandomMock;
import org.cryptomator.cryptolib.internal.FileHeaderParts;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.US_ASCII;

public class UvfContentCodecTest {

	private static final String HEADER_VECTOR = "dXZmAKQ0W7cAAAAAAAAAAAAAAAA/UGgFA8QGho7E1QTsHWyZIVFqabbGJ/TCwvp3StG0JTkKGj3hwERhnFmZek61Xtc=";

	private UvfSeeds seeds;

	@BeforeEach
	public void setup() {
		seeds = UvfSeedsTest.testSeeds();
		// reset cipher state to avoid InvalidAlgorithmParameterExceptions due to IV-reuse
		GcmTestHelper.reset((mode, key, params) -> {
			try (ObjectPool.Lease<Cipher> cipher = CipherSupplier.AES_GCM.encryptionCipher(key, params)) {
				cipher.get();
			}
		});
	}

	@AfterEach
	public void tearDown() {
		seeds.destroy();
	}

	@Test
	@DisplayName("layout is 68 byte header, 32740 byte payload, 32768 byte chunks, with EOF chunk")
	public void testLayout() {
		Assertions.assertEquals(68, UvfContentCodec.LAYOUT.headerSize());
		Assertions.assertEquals(32740, UvfContentCodec.LAYOUT.cleartextChunkSize());
		Assertions.assertEquals(32768, UvfContentCodec.LAYOUT.ciphertextChunkSize());
		Assertions.assertTrue(UvfContentCodec.LAYOUT.hasEofChunk());
	}

	@Test
	@DisplayName("create header with all-zero nonce and key")
	public void testCreateHeader() {
		UvfContentCodec codec = new UvfContentCodec(seeds, SecureRandomMock.NULL_RANDOM);
		FileHeaderParts header = codec.createHeader(UvfSeedsTest.TEST_SEED_ID);
		Assertions.assertArrayEquals(Base64.getDecoder().decode(HEADER_VECTOR), header.encrypted().array());
		Assertions.assertEquals(UvfSeedsTest.TEST_SEED_ID, header.seedId());
		Assertions.assertArrayEquals(new byte[12], header.nonce());
		Assertions.assertArrayEquals(new byte[32], header.fileKey().getEncoded());
	}

	@Test
	@DisplayName("decrypt header")
	public void testDecryptHeader() throws AuthenticationFailedException {
		UvfContentCodec codec = new UvfContentCodec(seeds, SecureRandomMock.NULL_RANDOM);
		ByteBuffer ciphertext = ByteBuffer.wrap(Base64.getDecoder().decode(HEADER_VECTOR));
		FileHeaderParts header = codec.decryptHeader(ciphertext);
		Assertions.assertEquals(UvfSeedsTest.TEST_SEED_ID, header.seedId());
		Assertions.assertArrayEquals(new byte[12], header.nonce());
		Assertions.assertArrayEquals(new byte[32], header.fileKey().getEncoded());
		Assertions.assertArrayEquals(ciphertext.array(), header.encrypted().array());
	}

	@Test
	@DisplayName("decrypt header with invalid tag / tampered ciphertext / wrong magic / unknown seed / too short")
	public void testDecryptInvalidHeaders() {
		UvfContentCodec codec = new UvfContentCodec(seeds, SecureRandomMock.NULL_RANDOM);
		Assertions.assertThrows(AuthenticationFailedException.class, () -> codec.decryptHeader(ByteBuffer.wrap(Base64.getDecoder().decode("dXZmAKQ0W7cAAAAAAAAAAAAAAAA/UGgFA8QGho7E1QTsHWyZIVFqabbGJ/TCwvp3StG0JTkKGj3hwERhnFmZek61XtX="))));
		Assertions.assertThrows(AuthenticationFailedException.class, () -> codec.decryptHeader(ByteBuffer.wrap(Base64.getDecoder().decode("dXZmAKQ0W7cAAAAAAAAAAAAAAAA/UGgFA8QGho7E1QTsHWyZIVFqabbGJ/XCwvp3StG0JTkKGj3hwERhnFmZek61Xtc="))));
		byte[] wrongMagic = Base64.getDecoder().decode(HEADER_VECTOR);
		wrongMagic[3] = 1;
		Assertions.assertThrows(IllegalArgumentException.class, () -> codec.decryptHeader(ByteBuffer.wrap(wrongMagic)));
		byte[] unknownSeed = Base64.getDecoder().decode(HEADER_VECTOR);
		unknownSeed[7] ^= 0x01;
		Assertions.assertThrows(IllegalArgumentException.class, () -> codec.decryptHeader(ByteBuffer.wrap(unknownSeed)));
		Assertions.assertThrows(IllegalArgumentException.class, () -> codec.decryptHeader(ByteBuffer.allocate(7)));
	}

	@Test
	@DisplayName("chunk round trip, AAD binds index and header nonce")
	public void testChunkRoundTrip() throws AuthenticationFailedException {
		UvfContentCodec codec = new UvfContentCodec(seeds, SecureRandomMock.PRNG_RANDOM);
		DestroyableSecretKey fileKey = new DestroyableSecretKey(new byte[32], "AES");
		byte[] headerNonce = new byte[12];
		ByteBuffer ciphertext = ByteBuffer.allocate(32768);
		codec.encryptChunk(headerNonce, fileKey, US_ASCII.encode("hello world"), ciphertext, 7);
		ciphertext.flip();
		Assertions.assertEquals(11 + 28, ciphertext.remaining());

		ByteBuffer cleartext = ByteBuffer.allocate(32740);
		codec.decryptChunk(headerNonce, fileKey, ciphertext.duplicate(), cleartext, 7);
		cleartext.flip();
		Assertions.assertEquals(US_ASCII.encode("hello world"), cleartext);

		Assertions.assertThrows(AuthenticationFailedException.class, () -> codec.decryptChunk(headerNonce, fileKey, ciphertext.duplicate(), ByteBuffer.allocate(32740), 8));
		byte[] otherNonce = new byte[12];
		otherNonce[0] = 1;
		Assertions.assertThrows(AuthenticationFailedException.class, () -> codec.decryptChunk(otherNonce, fileKey, ciphertext.duplicate(), ByteBuffer.allocate(32740), 7));
	}

	@Test
	@DisplayName("empty chunk (EOF chunk) is 28 bytes")
	public void testEmptyChunk() throws AuthenticationFailedException {
		UvfContentCodec codec = new UvfContentCodec(seeds, SecureRandomMock.PRNG_RANDOM);
		DestroyableSecretKey fileKey = new DestroyableSecretKey(new byte[32], "AES");
		ByteBuffer ciphertext = ByteBuffer.allocate(28);
		codec.encryptChunk(new byte[12], fileKey, ByteBuffer.allocate(0), ciphertext, 3);
		Assertions.assertFalse(ciphertext.hasRemaining());
		ciphertext.flip();
		ByteBuffer cleartext = ByteBuffer.allocate(32740);
		codec.decryptChunk(new byte[12], fileKey, ciphertext, cleartext, 3);
		Assertions.assertEquals(0, cleartext.position());
	}

	@Test
	@DisplayName("chunk index is a 32 bit unsigned integer")
	public void testChunkIndexRange() {
		UvfContentCodec codec = new UvfContentCodec(seeds, SecureRandomMock.PRNG_RANDOM);
		DestroyableSecretKey fileKey = new DestroyableSecretKey(new byte[32], "AES");
		Assertions.assertDoesNotThrow(() -> codec.encryptChunk(new byte[12], fileKey, ByteBuffer.allocate(1), ByteBuffer.allocate(100), 0xFFFFFFFFL));
		Assertions.assertThrows(IllegalArgumentException.class, () -> codec.encryptChunk(new byte[12], fileKey, ByteBuffer.allocate(1), ByteBuffer.allocate(100), 0x100000000L));
		Assertions.assertThrows(IllegalArgumentException.class, () -> codec.encryptChunk(new byte[12], fileKey, ByteBuffer.allocate(32741), ByteBuffer.allocate(40000), 0));
	}

	@Test
	@DisplayName("chunk index is encoded as 4 byte big endian AAD")
	public void testChunkIndexAad() throws Exception {
		// encrypt with the codec, then decrypt manually with a hand-built AAD to pin the on-disk format
		UvfContentCodec codec = new UvfContentCodec(seeds, SecureRandomMock.cycle((byte) 0x33));
		DestroyableSecretKey fileKey = new DestroyableSecretKey(new byte[32], "AES");
		byte[] headerNonce = new byte[12];
		Arrays.fill(headerNonce, (byte) 0x44);
		ByteBuffer ciphertext = ByteBuffer.allocate(100);
		codec.encryptChunk(headerNonce, fileKey, US_ASCII.encode("hello world"), ciphertext, 0x01020304L);
		ciphertext.flip();
		byte[] nonce = new byte[12];
		ciphertext.get(nonce);
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.DECRYPT_MODE, new javax.crypto.spec.SecretKeySpec(new byte[32], "AES"), new javax.crypto.spec.GCMParameterSpec(128, nonce));
		cipher.updateAAD(new byte[]{1, 2, 3, 4});
		cipher.updateAAD(headerNonce);
		byte[] rest = new byte[ciphertext.remaining()];
		ciphertext.get(rest);
		Assertions.assertArrayEquals("hello world".getBytes(US_ASCII), cipher.doFinal(rest));
	}

}
