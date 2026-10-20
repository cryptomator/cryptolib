package org.cryptomator.cryptolib.cvf8;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.CvfMasterkey;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;
import org.cryptomator.cryptolib.common.SecureRandomMock;
import org.cryptomator.cryptolib.internal.FileHeaderParts;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.US_ASCII;

class GcmCodecTest {

	private static final String HEADER_VECTOR = "AAAAAAAAAAAAAAAAMVi/wrKflJEHTsXTuvOdGHJgA8o3pip00aL1jnUGNY7dSrEoTUrhey+maVG6P0F2RBmZR74SjU0=";
	private static final String CHUNK_VECTOR = "MzMzMzMzMzMzMzMzbYvL7CusRmzk70Kn1QxFA5WQg/hgKeba4bln"; // echo -n "hello world" | openssl enc -aes-256-gcm -K 0 -iv 333333333333333333333333 -a

	private final CvfMasterkey masterkey = new CvfMasterkey(new byte[64]);

	@Test
	@DisplayName("layout is 68 byte header, 32768 byte payload, 32796 byte chunks, no EOF chunk")
	void testLayout() {
		GcmCodec codec = new GcmCodec(masterkey, SecureRandomMock.NULL_RANDOM);
		Assertions.assertEquals(68, codec.layout().headerSize());
		Assertions.assertEquals(32768, codec.layout().cleartextChunkSize());
		Assertions.assertEquals(32796, codec.layout().ciphertextChunkSize());
		Assertions.assertFalse(codec.layout().hasEofChunk());
	}

	@Test
	@DisplayName("create header with all-zero nonce and key")
	void testCreateHeader() {
		// echo -n "//////////8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==" | base64 --decode \
		// | openssl enc -aes-256-gcm -K 0000000000000000000000000000000000000000000000000000000000000000 -iv 00000000000000000000000000000000 -a
		// -> MVi/wrKflJEHTsXTuvOdGHJgA8o3pip00aL1jnUGNY7dSrEoTUrhew== (the tag is not produced by openssl, though)
		GcmCodec codec = new GcmCodec(masterkey, SecureRandomMock.NULL_RANDOM);
		FileHeaderParts header = codec.createHeader();
		Assertions.assertArrayEquals(Base64.getDecoder().decode(HEADER_VECTOR), header.encrypted().array());
		Assertions.assertArrayEquals(new byte[12], header.nonce());
		Assertions.assertArrayEquals(new byte[32], header.fileKey().getEncoded());
	}

	@Test
	@DisplayName("decrypt header")
	void testDecryptHeader() throws AuthenticationFailedException {
		GcmCodec codec = new GcmCodec(masterkey, SecureRandomMock.NULL_RANDOM);
		ByteBuffer ciphertext = ByteBuffer.wrap(Base64.getDecoder().decode(HEADER_VECTOR));
		FileHeaderParts header = codec.decryptHeader(ciphertext);
		Assertions.assertArrayEquals(new byte[12], header.nonce());
		Assertions.assertArrayEquals(new byte[32], header.fileKey().getEncoded());
		Assertions.assertArrayEquals(ciphertext.array(), header.encrypted().array());
	}

	@Test
	@DisplayName("decrypt too short header")
	void testDecryptTooShortHeader() {
		GcmCodec codec = new GcmCodec(masterkey, SecureRandomMock.NULL_RANDOM);
		Assertions.assertThrows(IllegalArgumentException.class, () -> codec.decryptHeader(ByteBuffer.allocate(7)));
	}

	@Test
	@DisplayName("decrypt header with invalid tag")
	void testDecryptHeaderWithInvalidTag() {
		GcmCodec codec = new GcmCodec(masterkey, SecureRandomMock.NULL_RANDOM);
		ByteBuffer ciphertext = ByteBuffer.wrap(Base64.getDecoder().decode("AAAAAAAAAAAAAAAAMVi/wrKflJEHTsXTuvOdGHJgA8o3pip00aL1jnUGNY7dSrEoTUrhey+maVG6P0F2RBmZR74SjUA="));
		Assertions.assertThrows(AuthenticationFailedException.class, () -> codec.decryptHeader(ciphertext));
	}

	@Test
	@DisplayName("encrypt chunk")
	void testEncryptChunk() {
		GcmCodec codec = new GcmCodec(masterkey, SecureRandomMock.cycle((byte) 0x33));
		ByteBuffer ciphertext = ByteBuffer.allocate(100);
		codec.encryptChunk(new byte[12], zeroKey(), US_ASCII.encode("hello world"), ciphertext, 0);
		ciphertext.flip();
		Assertions.assertEquals(ByteBuffer.wrap(Base64.getDecoder().decode(CHUNK_VECTOR)), ciphertext);
	}

	@Test
	@DisplayName("encrypt chunk with too small ciphertext buffer")
	void testEncryptChunkWithTooSmallBuffer() {
		GcmCodec codec = new GcmCodec(masterkey, SecureRandomMock.cycle((byte) 0x33));
		ByteBuffer ciphertext = ByteBuffer.allocate(11 + 27);
		Assertions.assertThrows(IllegalArgumentException.class, () -> codec.encryptChunk(new byte[12], zeroKey(), US_ASCII.encode("hello world"), ciphertext, 0));
	}

	@Test
	@DisplayName("decrypt chunk")
	void testDecryptChunk() throws AuthenticationFailedException {
		GcmCodec codec = new GcmCodec(masterkey, SecureRandomMock.NULL_RANDOM);
		ByteBuffer cleartext = ByteBuffer.allocate(32768);
		codec.decryptChunk(new byte[12], zeroKey(), ByteBuffer.wrap(Base64.getDecoder().decode(CHUNK_VECTOR)), cleartext, 0);
		cleartext.flip();
		Assertions.assertEquals(US_ASCII.encode("hello world"), cleartext);
	}

	@Test
	@DisplayName("decrypt chunk with wrong index")
	void testDecryptChunkWithWrongIndex() {
		GcmCodec codec = new GcmCodec(masterkey, SecureRandomMock.NULL_RANDOM);
		ByteBuffer cleartext = ByteBuffer.allocate(32768);
		Assertions.assertThrows(AuthenticationFailedException.class, () -> codec.decryptChunk(new byte[12], zeroKey(), ByteBuffer.wrap(Base64.getDecoder().decode(CHUNK_VECTOR)), cleartext, 1));
	}

	@Test
	@DisplayName("decrypt chunk with too small cleartext buffer")
	void testDecryptChunkWithTooSmallBuffer() {
		GcmCodec codec = new GcmCodec(masterkey, SecureRandomMock.NULL_RANDOM);
		ByteBuffer cleartext = ByteBuffer.allocate(10);
		Assertions.assertThrows(IllegalArgumentException.class, () -> codec.decryptChunk(new byte[12], zeroKey(), ByteBuffer.wrap(Base64.getDecoder().decode(CHUNK_VECTOR)), cleartext, 0));
	}

	private static DestroyableSecretKey zeroKey() {
		return new DestroyableSecretKey(new byte[32], "AES");
	}

}
