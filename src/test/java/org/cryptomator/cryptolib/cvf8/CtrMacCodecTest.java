package org.cryptomator.cryptolib.cvf8;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.CvfMasterkey;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;
import org.cryptomator.cryptolib.common.SecureRandomMock;
import org.cryptomator.cryptolib.internal.FileHeaderParts;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.US_ASCII;

public class CtrMacCodecTest {

	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.NULL_RANDOM;
	private static final String HEADER_VECTOR = "AAAAAAAAAAAAAAAAAAAAACNqP4ddv3Z2rUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga24VjC86+zlHN49BfMdzvHF3f9EE0LSnRLSsu6ps3IRcJg==";
	private static final String CHUNK_VECTOR = "AAAAAAAAAAAAAAAAAAAAALTwrBTNYP7m3yTGKlhka9WPvX1Lpn5EYfVxlyX1ISgRXtdRnivM7r6F3Og=";

	private CtrMacCodec codec;

	@BeforeEach
	public void setup() {
		codec = new CtrMacCodec(new CvfMasterkey(new byte[64]), RANDOM_MOCK);
	}

	@Test
	@DisplayName("layout is 88 byte header, 32768 byte payload, 32816 byte chunks, no EOF chunk")
	public void testLayout() {
		Assertions.assertEquals(88, codec.layout().headerSize());
		Assertions.assertEquals(32768, codec.layout().cleartextChunkSize());
		Assertions.assertEquals(32816, codec.layout().ciphertextChunkSize());
		Assertions.assertFalse(codec.layout().hasEofChunk());
	}

	@Test
	@DisplayName("create header with all-zero nonce and key")
	public void testCreateHeader() {
		// echo -n "//////////8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==" | base64 --decode \
		// | openssl enc -aes-256-ctr -K 0000000000000000000000000000000000000000000000000000000000000000 -iv 00000000000000000000000000000000 | base64
		// -> I2o/h12/dnatSKIUkoQgh1MPivvHRTa5qWO08cTLc4vOp0A9TWBrbg==
		// mac nonce + encrypted payload (openssl dgst -sha256 -mac HMAC -macopt hexkey:00..00 -binary), concat nonce + encrypted payload + mac:
		FileHeaderParts header = codec.createHeader();
		Assertions.assertArrayEquals(Base64.getDecoder().decode(HEADER_VECTOR), header.encrypted().array());
		Assertions.assertArrayEquals(new byte[16], header.nonce());
		Assertions.assertArrayEquals(new byte[32], header.fileKey().getEncoded());
	}

	@Test
	@DisplayName("decrypt header")
	public void testDecryptHeader() throws AuthenticationFailedException {
		ByteBuffer ciphertext = ByteBuffer.wrap(Base64.getDecoder().decode(HEADER_VECTOR));
		FileHeaderParts header = codec.decryptHeader(ciphertext);
		Assertions.assertArrayEquals(new byte[16], header.nonce());
		Assertions.assertArrayEquals(new byte[32], header.fileKey().getEncoded());
		Assertions.assertArrayEquals(ciphertext.array(), header.encrypted().array());
	}

	@Test
	@DisplayName("decrypt too short header")
	public void testDecryptTooShortHeader() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> codec.decryptHeader(ByteBuffer.allocate(7)));
	}

	@Test
	@DisplayName("decrypt header with invalid MAC")
	public void testDecryptHeaderWithInvalidMac() {
		ByteBuffer ciphertext = ByteBuffer.wrap(Base64.getDecoder().decode("AAAAAAAAAAAAAAAAAAAAANyVwHiiQImjrUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga26lJzstK9RUv1hj5zDC4wC9FgMfoVE1mD0HnuENuYXkJa=="));
		Assertions.assertThrows(AuthenticationFailedException.class, () -> codec.decryptHeader(ciphertext));
	}

	@Test
	@DisplayName("encrypt chunk")
	public void testEncryptChunk() {
		ByteBuffer ciphertext = ByteBuffer.allocate(100);
		codec.encryptChunk(new byte[16], zeroKey(), US_ASCII.encode("hello world"), ciphertext, 0);
		ciphertext.flip();
		Assertions.assertEquals(ByteBuffer.wrap(Base64.getDecoder().decode(CHUNK_VECTOR)), ciphertext);
	}

	@Test
	@DisplayName("encrypt chunk into offset buffer with exact remaining size")
	public void testEncryptChunkIntoExactBuffer() {
		ByteBuffer ciphertext = ByteBuffer.allocate(11 + 48 + 3);
		ciphertext.position(3);
		codec.encryptChunk(new byte[16], zeroKey(), US_ASCII.encode("hello world"), ciphertext, 0);
		Assertions.assertFalse(ciphertext.hasRemaining());
		ciphertext.position(3);
		Assertions.assertEquals(ByteBuffer.wrap(Base64.getDecoder().decode(CHUNK_VECTOR)), ciphertext);
	}

	@Test
	@DisplayName("encrypt chunk with too small ciphertext buffer")
	public void testEncryptChunkWithTooSmallBuffer() {
		ByteBuffer ciphertext = ByteBuffer.allocate(11 + 47);
		Assertions.assertThrows(IllegalArgumentException.class, () -> codec.encryptChunk(new byte[16], zeroKey(), US_ASCII.encode("hello world"), ciphertext, 0));
	}

	@Test
	@DisplayName("decrypt chunk")
	public void testDecryptChunk() throws AuthenticationFailedException {
		ByteBuffer cleartext = ByteBuffer.allocate(32768);
		codec.decryptChunk(new byte[16], zeroKey(), ByteBuffer.wrap(Base64.getDecoder().decode(CHUNK_VECTOR)), cleartext, 0);
		cleartext.flip();
		Assertions.assertEquals(US_ASCII.encode("hello world"), cleartext);
	}

	@Test
	@DisplayName("decrypt chunk with wrong index")
	public void testDecryptChunkWithWrongIndex() {
		ByteBuffer cleartext = ByteBuffer.allocate(32768);
		Assertions.assertThrows(AuthenticationFailedException.class, () -> codec.decryptChunk(new byte[16], zeroKey(), ByteBuffer.wrap(Base64.getDecoder().decode(CHUNK_VECTOR)), cleartext, 1));
	}

	@Test
	@DisplayName("decrypt chunk with wrong header nonce")
	public void testDecryptChunkWithWrongHeaderNonce() {
		ByteBuffer cleartext = ByteBuffer.allocate(32768);
		byte[] nonce = new byte[16];
		nonce[0] = 1;
		Assertions.assertThrows(AuthenticationFailedException.class, () -> codec.decryptChunk(nonce, zeroKey(), ByteBuffer.wrap(Base64.getDecoder().decode(CHUNK_VECTOR)), cleartext, 0));
	}

	@Test
	@DisplayName("decrypt chunk with too small cleartext buffer")
	public void testDecryptChunkWithTooSmallBuffer() {
		ByteBuffer cleartext = ByteBuffer.allocate(10);
		Assertions.assertThrows(IllegalArgumentException.class, () -> codec.decryptChunk(new byte[16], zeroKey(), ByteBuffer.wrap(Base64.getDecoder().decode(CHUNK_VECTOR)), cleartext, 0));
	}

	@Test
	@DisplayName("mac is valid after encryption")
	public void testMacIsValidAfterEncryption() {
		ByteBuffer ciphertext = ByteBuffer.allocate(codec.layout().ciphertextChunkSize());
		codec.encryptChunk(new byte[16], zeroKey(), US_ASCII.encode("asd"), ciphertext, 42L);
		ciphertext.flip();
		Assertions.assertTrue(codec.checkChunkMac(new byte[16], 42L, ciphertext));
		Assertions.assertFalse(codec.checkChunkMac(new byte[16], 43L, ciphertext));
	}

	private static DestroyableSecretKey zeroKey() {
		return new DestroyableSecretKey(new byte[32], "AES");
	}

}
