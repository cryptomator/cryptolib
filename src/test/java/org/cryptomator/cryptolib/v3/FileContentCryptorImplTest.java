package org.cryptomator.cryptolib.v3;

import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.api.UVFMasterkey;
import org.cryptomator.cryptolib.common.CipherSupplier;
import org.cryptomator.cryptolib.common.DecryptingReadableByteChannel;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;
import org.cryptomator.cryptolib.common.EncryptingWritableByteChannel;
import org.cryptomator.cryptolib.common.GcmTestHelper;
import org.cryptomator.cryptolib.common.ObjectPool;
import org.cryptomator.cryptolib.common.SecureRandomMock;
import org.cryptomator.cryptolib.common.SeekableByteChannelMock;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;

import javax.crypto.Cipher;
import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.cryptomator.cryptolib.v3.Constants.GCM_NONCE_SIZE;
import static org.cryptomator.cryptolib.v3.Constants.GCM_TAG_SIZE;

public class FileContentCryptorImplTest {

	// AES-GCM implementation requires non-repeating nonces, still we need deterministic nonces for testing
	private static final SecureRandom CSPRNG = Mockito.spy(SecureRandomMock.cycle((byte) 0xF0, (byte) 0x0F));
	private static final byte[] SEED = Base64.getUrlDecoder().decode("fP4V4oAjsUw5DqackAvLzA0oP1kAQZ0f5YFZQviXSuU");
	private static final int SEED_ID = 1925996179; // derived from SEED and KDF_SALT, see UVFMasterkeyTest
	private static final Map<Integer, byte[]> SEEDS = Collections.singletonMap(SEED_ID, SEED);
	private static final byte[] KDF_SALT = Base64.getUrlDecoder().decode("HE4OP-2vyfLLURicF1XmdIIsWv0Zs6MobLKROUIEhQY");
	private static final UVFMasterkey MASTERKEY = new UVFMasterkey(SEEDS, KDF_SALT, SEED_ID, SEED_ID);

	// "hello world" with header nonce 0x55.., content key 0x77.., chunk nonce 0xAA..; a single partial chunk, so no EOF chunk follows
	private static final String HELLO_WORLD_FILE = "dXZmAXLMXpNVVVVVVVVVVVVVVVUcowd1FbpM8eMdABtmD/I3RO0n0rV2V3iDYXb++QHGHjTzzcsPP/83Bh24Q4Tpk6Oqqqqqqqqqqqqqqqq3J+X9CFc6SL5hl91LYM/wY4yOVcDcCTO0f7M=";

	private FileHeaderImpl header;
	private FileHeaderCryptorImpl headerCryptor;
	private FileContentCryptorImpl fileContentCryptor;
	private Cryptor cryptor;

	@BeforeEach
	public void setup() {
		header = new FileHeaderImpl(SEED_ID, new byte[FileHeaderImpl.NONCE_LEN], new DestroyableSecretKey(new byte[FileHeaderImpl.CONTENT_KEY_LEN], "AES"));
		headerCryptor = new FileHeaderCryptorImpl(MASTERKEY, CSPRNG, SEED_ID);
		fileContentCryptor = new FileContentCryptorImpl(CSPRNG);
		cryptor = Mockito.mock(Cryptor.class);
		Mockito.doReturn(fileContentCryptor).when(cryptor).fileContentCryptor();
		Mockito.doReturn(headerCryptor).when(cryptor).fileHeaderCryptor();

		// reset cipher state to avoid InvalidAlgorithmParameterExceptions due to IV-reuse
		GcmTestHelper.reset((mode, key, params) -> {
			try (ObjectPool.Lease<Cipher> cipher = CipherSupplier.AES_GCM.encryptionCipher(key, params)) {
				cipher.get();
			}
		});
	}

	@Test
	public void testChunkSizes() {
		Assertions.assertEquals(32740, fileContentCryptor.cleartextChunkSize());
		Assertions.assertEquals(32768, fileContentCryptor.ciphertextChunkSize());
	}

	@DisplayName("ciphertext size incl. EOF chunk")
	@ParameterizedTest(name = "ciphertextSize({0}) == {1}")
	@CsvSource({
			"0, 28", // empty file: EOF chunk only
			"1, 29",
			"32739, 32767",
			"32740, 32796", // one full chunk + EOF chunk
			"32741, 32797",
			"65480, 65564", // two full chunks + EOF chunk
	})
	public void testCiphertextSize(long cleartextSize, long ciphertextSize) {
		Assertions.assertEquals(ciphertextSize, fileContentCryptor.ciphertextSize(cleartextSize));
	}

	@DisplayName("cleartext size incl. EOF chunk")
	@ParameterizedTest(name = "cleartextSize({1}) == {0}")
	@CsvSource({
			"0, 28",
			"1, 29",
			"32739, 32767",
			"32740, 32796",
			"32741, 32797",
			"65480, 65564",
	})
	public void testCleartextSize(long cleartextSize, long ciphertextSize) {
		Assertions.assertEquals(cleartextSize, fileContentCryptor.cleartextSize(ciphertextSize));
	}

	@DisplayName("cleartext size of invalid ciphertext sizes")
	@ParameterizedTest(name = "cleartextSize({0}) throws")
	@ValueSource(longs = {
			-1,
			0, // EOF chunk missing
			27, // impossible chunk size
			32768, // full chunk without EOF chunk
			32769, // full chunk + 1..27 bytes
			32795,
			65536,
	})
	public void testCleartextSizeOfInvalidCiphertextSize(long ciphertextSize) {
		Assertions.assertThrows(IllegalArgumentException.class, () -> fileContentCryptor.cleartextSize(ciphertextSize));
	}

	@Test
	public void testCiphertextSizeOfNegativeCleartextSize() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> fileContentCryptor.ciphertextSize(-1));
	}

	@Test
	public void testDecryptedEncryptedEqualsPlaintext() throws AuthenticationFailedException {
		DestroyableSecretKey fileKey = new DestroyableSecretKey(new byte[16], "AES");
		ByteBuffer ciphertext = ByteBuffer.allocate(fileContentCryptor.ciphertextChunkSize());
		ByteBuffer cleartext = ByteBuffer.allocate(fileContentCryptor.cleartextChunkSize());
		fileContentCryptor.encryptChunk(UTF_8.encode("asd"), ciphertext, 42l, new byte[12], fileKey);
		ciphertext.flip();
		fileContentCryptor.decryptChunk(ciphertext, cleartext, 42l, new byte[12], fileKey);
		cleartext.flip();
		Assertions.assertEquals(UTF_8.encode("asd"), cleartext);
	}

	@Test
	@DisplayName("encrypt and decrypt empty (EOF) chunk")
	public void testDecryptedEncryptedEmptyChunk() throws AuthenticationFailedException {
		DestroyableSecretKey fileKey = new DestroyableSecretKey(new byte[16], "AES");
		ByteBuffer ciphertext = fileContentCryptor.encryptChunk(ByteBuffer.allocate(0), 1, header);
		Assertions.assertEquals(GCM_NONCE_SIZE + GCM_TAG_SIZE, ciphertext.remaining());
		ByteBuffer cleartext = fileContentCryptor.decryptChunk(ciphertext, 1, header, true);
		Assertions.assertEquals(0, cleartext.remaining());
	}

	@Nested
	public class Encryption {

		@BeforeEach
		public void resetGcmNonce() {
			// reset cipher state to avoid InvalidAlgorithmParameterExceptions due to IV-reuse
			GcmTestHelper.reset((mode, key, params) -> {
				try (ObjectPool.Lease<Cipher> cipher = CipherSupplier.AES_GCM.encryptionCipher(key, params)) {
					cipher.get();
				}
			});
		}

		@DisplayName("encrypt chunk with invalid size")
		@ParameterizedTest(name = "cleartext size: {0}")
		@ValueSource(ints = {Constants.PAYLOAD_SIZE + 1})
		public void testEncryptChunkOfInvalidSize(int size) {
			ByteBuffer cleartext = ByteBuffer.allocate(size);

			Assertions.assertThrows(IllegalArgumentException.class, () -> {
				fileContentCryptor.encryptChunk(cleartext, 0, header);
			});
		}

		@DisplayName("encrypt chunk with invalid chunk number")
		@ParameterizedTest(name = "chunk number: {0}")
		@ValueSource(longs = {-1L, Constants.MAX_CHUNK_NUMBER + 1L})
		public void testEncryptChunkWithInvalidNumber(long number) {
			ByteBuffer cleartext = ByteBuffer.allocate(Constants.PAYLOAD_SIZE);

			Assertions.assertThrows(IllegalArgumentException.class, () -> {
				fileContentCryptor.encryptChunk(cleartext, number, header);
			});
		}

		@Test
		@DisplayName("encrypt chunk")
		public void testChunkEncryption() {
			Mockito.doAnswer(invocation -> {
				byte[] nonce = invocation.getArgument(0);
				Arrays.fill(nonce, (byte) 0x33);
				return null;
			}).when(CSPRNG).nextBytes(Mockito.any());
			ByteBuffer cleartext = StandardCharsets.US_ASCII.encode(CharBuffer.wrap("hello world"));
			ByteBuffer ciphertext = fileContentCryptor.encryptChunk(cleartext, 0, header);
			// AAD = 4 byte big-endian chunk number 0 + 12 byte header nonce 0
			byte[] expected = BaseEncoding.base64().decode("MzMzMzMzMzMzMzMzbYvL7CusRmzk70LIx7uwkxm5p10QN85Kw9sM");
			Assertions.assertEquals(ByteBuffer.wrap(expected), ciphertext);
		}

		@Test
		@DisplayName("encrypt chunk with offset ByteBuffer")
		public void testChunkEncryptionWithByteBufferView() {
			Mockito.doAnswer(invocation -> {
				byte[] nonce = invocation.getArgument(0);
				Arrays.fill(nonce, (byte) 0x33);
				return null;
			}).when(CSPRNG).nextBytes(Mockito.any());
			ByteBuffer cleartext = US_ASCII.encode("12345hello world12345");
			cleartext.position(5).limit(16);
			ByteBuffer ciphertext = fileContentCryptor.encryptChunk(cleartext, 0, header);
			byte[] expected = BaseEncoding.base64().decode("MzMzMzMzMzMzMzMzbYvL7CusRmzk70LIx7uwkxm5p10QN85Kw9sM");
			Assertions.assertEquals(ByteBuffer.wrap(expected), ciphertext);
		}

		@Test
		@DisplayName("encrypt chunk with too small ciphertext buffer")
		public void testChunkEncryptionWithBufferUnderflow() {
			ByteBuffer cleartext = StandardCharsets.US_ASCII.encode(CharBuffer.wrap("hello world"));
			ByteBuffer ciphertext = ByteBuffer.allocate(Constants.CHUNK_SIZE - 1);
			Assertions.assertThrows(IllegalArgumentException.class, () -> {
				fileContentCryptor.encryptChunk(cleartext, ciphertext, 0, header);
			});
		}

		@Test
		@DisplayName("encrypt file")
		public void testFileEncryption() throws IOException {
			Mockito.doAnswer(invocation -> {
				byte[] nonce = invocation.getArgument(0);
				Arrays.fill(nonce, (byte) 0x55); // header nonce
				return null;
			}).doAnswer(invocation -> {
				byte[] nonce = invocation.getArgument(0);
				Arrays.fill(nonce, (byte) 0x77); // header content key
				return null;
			}).doAnswer(invocation -> {
				byte[] nonce = invocation.getArgument(0);
				Arrays.fill(nonce, (byte) 0xAA); // chunk nonce
				return null;
			}).when(CSPRNG).nextBytes(Mockito.any());
			ByteBuffer dst = ByteBuffer.allocate(200);
			SeekableByteChannel dstCh = new SeekableByteChannelMock(dst);
			try (WritableByteChannel ch = new EncryptingWritableByteChannel(dstCh, cryptor)) {
				ch.write(StandardCharsets.US_ASCII.encode("hello world"));
			}
			dst.flip();
			byte[] ciphertext = new byte[dst.remaining()];
			dst.get(ciphertext);
			byte[] expected = BaseEncoding.base64().decode(HELLO_WORLD_FILE);
			Assertions.assertArrayEquals(expected, ciphertext);
		}

		@Test
		@DisplayName("encrypt empty file")
		public void testEmptyFileEncryption() throws IOException {
			ByteBuffer dst = ByteBuffer.allocate(200);
			SeekableByteChannel dstCh = new SeekableByteChannelMock(dst);
			try (WritableByteChannel ch = new EncryptingWritableByteChannel(dstCh, cryptor)) {
				// nothing to write
			}
			dst.flip();
			Assertions.assertEquals(FileHeaderImpl.SIZE + Constants.CHUNK_OVERHEAD, dst.remaining(), "header + EOF chunk");
		}

	}

	@Nested
	public class Decryption {

		@DisplayName("decrypt chunk with invalid size")
		@ParameterizedTest(name = "ciphertext size: {0}")
		@ValueSource(ints = {0, Constants.GCM_NONCE_SIZE + Constants.GCM_TAG_SIZE - 1, Constants.CHUNK_SIZE + 1})
		public void testDecryptChunkOfInvalidSize(int size) {
			ByteBuffer ciphertext = ByteBuffer.allocate(size);

			Assertions.assertThrows(IllegalArgumentException.class, () -> {
				fileContentCryptor.decryptChunk(ciphertext, 0, header, true);
			});
		}

		@Test
		@DisplayName("decrypt chunk")
		public void testChunkDecryption() throws AuthenticationFailedException {
			ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("VVVVVVVVVVVVVVVVnHVdh+EbedvPeiDfG2Fm8hDO8ICgkDwxzpOE"));
			ByteBuffer cleartext = fileContentCryptor.decryptChunk(ciphertext, 0, header, true);
			ByteBuffer expected = StandardCharsets.US_ASCII.encode("hello world");
			Assertions.assertEquals(expected, cleartext);
		}

		@Test
		@DisplayName("decrypt chunk with wrong chunk number")
		public void testChunkDecryptionWithWrongChunkNumber() {
			ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("VVVVVVVVVVVVVVVVnHVdh+EbedvPeiDfG2Fm8hDO8ICgkDwxzpOE"));
			Assertions.assertThrows(AuthenticationFailedException.class, () -> {
				fileContentCryptor.decryptChunk(ciphertext, 1, header, true);
			});
		}

		@Test
		@DisplayName("decrypt chunk with offset ByteBuffer")
		public void testChunkDecryptionWithByteBufferView() throws AuthenticationFailedException {
			byte[] actualCiphertext = BaseEncoding.base64().decode("VVVVVVVVVVVVVVVVnHVdh+EbedvPeiDfG2Fm8hDO8ICgkDwxzpOE");
			ByteBuffer ciphertext = ByteBuffer.allocate(100);
			ciphertext.position(10);
			ciphertext.put(actualCiphertext);
			ciphertext.position(10).limit(10 + actualCiphertext.length);
			ByteBuffer cleartext = fileContentCryptor.decryptChunk(ciphertext, 0, header, true);
			ByteBuffer expected = US_ASCII.encode("hello world");
			Assertions.assertEquals(expected, cleartext);
		}

		@Test
		@DisplayName("decrypt chunk with too small cleartext buffer")
		public void testChunkDecryptionWithBufferUnderflow() {
			ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("VVVVVVVVVVVVVVVVnHVdh+EbedvPeiDfG2Fm8hDO8ICgkDwxzpOE"));
			ByteBuffer cleartext = ByteBuffer.allocate(Constants.PAYLOAD_SIZE - 1);
			Assertions.assertThrows(IllegalArgumentException.class, () -> {
				fileContentCryptor.decryptChunk(ciphertext, cleartext, 0, header, true);
			});
		}

		@Test
		@DisplayName("decrypt file")
		public void testFileDecryption() throws IOException {
			byte[] ciphertext = BaseEncoding.base64().decode(HELLO_WORLD_FILE);
			ReadableByteChannel ciphertextCh = Channels.newChannel(new ByteArrayInputStream(ciphertext));

			ByteBuffer result = ByteBuffer.allocate(20);
			try (ReadableByteChannel cleartextCh = new DecryptingReadableByteChannel(ciphertextCh, cryptor, true)) {
				int read = cleartextCh.read(result);
				Assertions.assertEquals(11, read);
				byte[] expected = "hello world".getBytes(StandardCharsets.US_ASCII);
				Assertions.assertArrayEquals(expected, Arrays.copyOfRange(result.array(), 0, read));
			}
		}

		@Test
		@DisplayName("decrypt file with unauthentic file header")
		public void testDecryptionWithTooShortHeader() throws InterruptedException, IOException {
			byte[] ciphertext = BaseEncoding.base64().decode("AAAAAAAA");
			ReadableByteChannel ciphertextCh = Channels.newChannel(new ByteArrayInputStream(ciphertext));

			try (ReadableByteChannel cleartextCh = new DecryptingReadableByteChannel(ciphertextCh, cryptor, true)) {
				Assertions.assertThrows(EOFException.class, () -> {
					cleartextCh.read(ByteBuffer.allocate(3));
				});
			}
		}

		@Test
		@DisplayName("decrypt file consisting of header only (EOF chunk missing)")
		public void testDecryptionWithoutEofChunk() throws IOException {
			byte[] ciphertext = Arrays.copyOf(BaseEncoding.base64().decode(HELLO_WORLD_FILE), FileHeaderImpl.SIZE);
			ReadableByteChannel ciphertextCh = Channels.newChannel(new ByteArrayInputStream(ciphertext));

			try (ReadableByteChannel cleartextCh = new DecryptingReadableByteChannel(ciphertextCh, cryptor, true)) {
				IOException thrown = Assertions.assertThrows(IOException.class, () -> {
					cleartextCh.read(ByteBuffer.allocate(3));
				});
				MatcherAssert.assertThat(thrown.getCause(), CoreMatchers.instanceOf(AuthenticationFailedException.class));
			}
		}

		@DisplayName("decrypt unauthentic chunk")
		@ParameterizedTest(name = "unauthentic {1}")
		@CsvSource(value = {
				"VFVVVVVVVVVVVVVVnHVdh+EbedvPeiDfG2Fm8hDO8ICgkDwxzpOE, NONCE",
				"VVVVVVVVVVVVVVVVnXVdh+EbedvPeiDfG2Fm8hDO8ICgkDwxzpOE, CONTENT",
				"VVVVVVVVVVVVVVVVnHVdh+EbedvPeiDfG2Fm8hDO8ICgkDwxzpOF, TAG",
		})
		public void testUnauthenticChunkDecryption(String chunkData, String ignored) {
			ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode(chunkData));

			Assertions.assertThrows(AuthenticationFailedException.class, () -> {
				fileContentCryptor.decryptChunk(ciphertext, 0, header, true);
			});
		}

		@DisplayName("decrypt unauthentic file")
		@ParameterizedTest(name = "unauthentic {1} in first chunk")
		@CsvSource(value = {
				"dXZmAXLMXpNVVVVVVVVVVVVVVVUcowd1FbpM8eMdABtmD/I3RO0n0rV2V3iDYXb++QHGHjTzzcsPP/83Bh24Q4Tpk6Orqqqqqqqqqqqqqqq3J+X9CFc6SL5hl91LYM/wY4yOVcDcCTO0f7M=, NONCE",
				"dXZmAXLMXpNVVVVVVVVVVVVVVVUcowd1FbpM8eMdABtmD/I3RO0n0rV2V3iDYXb++QHGHjTzzcsPP/83Bh24Q4Tpk6Oqqqqqqqqqqqqqqqq2J+X9CFc6SL5hl91LYM/wY4yOVcDcCTO0f7M=, CONTENT",
				"dXZmAXLMXpNVVVVVVVVVVVVVVVUcowd1FbpM8eMdABtmD/I3RO0n0rV2V3iDYXb++QHGHjTzzcsPP/83Bh24Q4Tpk6Oqqqqqqqqqqqqqqqq3J+X9CFc6SL5hl91LYM/wY4yOVcDcCTO0f7I=, TAG",
		})
		public void testDecryptionWithUnauthenticFirstChunk(String fileData, String ignored) throws IOException {
			byte[] ciphertext = BaseEncoding.base64().decode(fileData);

			ReadableByteChannel ciphertextCh = Channels.newChannel(new ByteArrayInputStream(ciphertext));

			try (ReadableByteChannel cleartextCh = new DecryptingReadableByteChannel(ciphertextCh, cryptor, true)) {
				IOException thrown = Assertions.assertThrows(IOException.class, () -> {
					cleartextCh.read(ByteBuffer.allocate(3));
				});
				MatcherAssert.assertThat(thrown.getCause(), CoreMatchers.instanceOf(AuthenticationFailedException.class));
			}
		}

		@Test
		@DisplayName("decrypt chunk with unauthentic tag but skipping authentication")
		public void testChunkDecryptionWithUnauthenticTagSkipAuth() {
			ByteBuffer dummyCiphertext = ByteBuffer.allocate(GCM_NONCE_SIZE + GCM_TAG_SIZE);
			FileHeader header = Mockito.mock(FileHeader.class);
			Assertions.assertThrows(UnsupportedOperationException.class, () -> {
				fileContentCryptor.decryptChunk(dummyCiphertext, 0, header, false);
			});
		}

	}

}
