package org.cryptomator.cryptolib.cvf8;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.CipherCombo;
import org.cryptomator.cryptolib.api.CvfMasterkey;
import org.cryptomator.cryptolib.api.VaultFile;
import org.cryptomator.cryptolib.common.InMemoryCiphertext;
import org.cryptomator.cryptolib.common.SecureRandomMock;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.io.EOFException;
import java.io.IOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

/**
 * Range access ({@link VaultFile#read}, {@link VaultFile#write}, {@link VaultFile#truncate}) against an in-memory ciphertext, for both CVF8 cipher combos.
 */
class Cvf8VaultFileTest {

	private static final SecureRandom CSPRNG = SecureRandomMock.PRNG_RANDOM;
	private static final int CHUNK = 32768;

	private static Cvf8Vault vault(CipherCombo combo) {
		CvfMasterkey key = new CvfMasterkey(new byte[64]);
		Cvf8ContentCodec codec = combo == CipherCombo.SIV_CTRMAC ? new CtrMacCodec(key, CSPRNG) : new GcmCodec(key, CSPRNG);
		return new Cvf8Vault(key, "vault-id", URI.create("masterkeyfile:masterkey.cryptomator"), combo, 220, codec);
	}

	@ParameterizedTest(name = "{0}: write sequentially, read back in odd-sized pieces")
	@EnumSource(CipherCombo.class)
	@DisplayName("write then read")
	void testWriteThenRead(CipherCombo combo) throws IOException {
		byte[] cleartext = randomBytes(3 * CHUNK + 1234, 1);
		InMemoryCiphertext ciphertext = new InMemoryCiphertext();
		try (Cvf8Vault vault = vault(combo); VaultFile file = vault.createFile()) {
			Assertions.assertEquals(0, file.size());
			Assertions.assertEquals(0, ciphertext.size());
			Assertions.assertEquals(-1, file.read(0, ByteBuffer.allocate(10), ciphertext));

			// write in pieces of 1000 bytes:
			ByteBuffer src = ByteBuffer.wrap(cleartext);
			long pos = 0;
			while (src.hasRemaining()) {
				ByteBuffer piece = src.slice();
				piece.limit(Math.min(1000, piece.remaining()));
				int written = file.write(pos, piece, ciphertext, ciphertext);
				Assertions.assertEquals(piece.limit(), written);
				pos += written;
				src.position(src.position() + written);
			}
			Assertions.assertEquals(cleartext.length, file.size());
			Assertions.assertEquals(vault.ciphertextSize(cleartext.length), ciphertext.size());

			// read back in pieces of 777 bytes:
			byte[] result = new byte[cleartext.length];
			ByteBuffer dst = ByteBuffer.wrap(result);
			pos = 0;
			while (dst.hasRemaining()) {
				ByteBuffer piece = dst.slice();
				piece.limit(Math.min(777, piece.remaining()));
				int read = file.read(pos, piece, ciphertext);
				Assertions.assertEquals(piece.limit(), read);
				pos += read;
				dst.position(dst.position() + read);
			}
			Assertions.assertArrayEquals(cleartext, result);
			Assertions.assertEquals(-1, file.read(cleartext.length, ByteBuffer.allocate(10), ciphertext));

			// the ciphertext is a regular file:
			Assertions.assertArrayEquals(cleartext, vault.decryptFile(ciphertext.toByteArray()));
		}
	}

	@ParameterizedTest(name = "{0}: read across chunk boundary")
	@EnumSource(CipherCombo.class)
	void testReadAcrossChunkBoundary(CipherCombo combo) throws IOException {
		byte[] cleartext = randomBytes(2 * CHUNK, 2);
		try (Cvf8Vault vault = vault(combo)) {
			InMemoryCiphertext ciphertext = new InMemoryCiphertext(vault.encryptFile(cleartext));
			try (VaultFile file = vault.openFile(ByteBuffer.wrap(ciphertext.toByteArray(), 0, vault.headerSize()), ciphertext.size())) {
				ByteBuffer dst = ByteBuffer.allocate(100);
				Assertions.assertEquals(100, file.read(CHUNK - 50, dst, ciphertext));
				Assertions.assertArrayEquals(Arrays.copyOfRange(cleartext, CHUNK - 50, CHUNK + 50), dst.array());
				// read past EOF is capped:
				ByteBuffer tail = ByteBuffer.allocate(100);
				Assertions.assertEquals(10, file.read(2 * CHUNK - 10, tail, ciphertext));
				Assertions.assertEquals(-1, file.read(2 * CHUNK, tail, ciphertext));
			}
		}
	}

	@ParameterizedTest(name = "{0}: overwrite inside a chunk and append")
	@EnumSource(CipherCombo.class)
	void testOverwriteAndAppend(CipherCombo combo) throws IOException {
		byte[] cleartext = randomBytes(CHUNK + 500, 3);
		try (Cvf8Vault vault = vault(combo)) {
			InMemoryCiphertext ciphertext = new InMemoryCiphertext(vault.encryptFile(cleartext));
			try (VaultFile file = vault.openFile(ByteBuffer.wrap(ciphertext.toByteArray(), 0, vault.headerSize()), ciphertext.size())) {
				// overwrite 10 bytes in the middle of chunk 0:
				file.write(100, ByteBuffer.wrap(new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}), ciphertext, ciphertext);
				Assertions.assertEquals(cleartext.length, file.size());
				// overwrite across the boundary:
				file.write(CHUNK - 5, ByteBuffer.wrap(new byte[10]), ciphertext, ciphertext);
				// append crossing into a new chunk:
				file.write(file.size(), ByteBuffer.wrap(new byte[CHUNK]), ciphertext, ciphertext);
				Assertions.assertEquals(2 * CHUNK + 500, file.size());
			}
			byte[] expected = Arrays.copyOf(cleartext, 2 * CHUNK + 500);
			System.arraycopy(new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 0, expected, 100, 10);
			Arrays.fill(expected, CHUNK - 5, CHUNK + 5, (byte) 0);
			Assertions.assertArrayEquals(expected, vault.decryptFile(ciphertext.toByteArray()));
		}
	}

	@ParameterizedTest(name = "{0}: writing beyond EOF zero-fills the gap")
	@EnumSource(CipherCombo.class)
	void testWriteBeyondEof(CipherCombo combo) throws IOException {
		InMemoryCiphertext ciphertext = new InMemoryCiphertext();
		try (Cvf8Vault vault = vault(combo)) {
			try (VaultFile file = vault.createFile()) {
				file.write(10, ByteBuffer.wrap(new byte[]{42}), ciphertext, ciphertext);
				Assertions.assertEquals(11, file.size());
				file.write(CHUNK + 1000, ByteBuffer.wrap(new byte[]{43}), ciphertext, ciphertext);
				Assertions.assertEquals(CHUNK + 1001, file.size());
			}
			byte[] expected = new byte[CHUNK + 1001];
			expected[10] = 42;
			expected[CHUNK + 1000] = 43;
			Assertions.assertArrayEquals(expected, vault.decryptFile(ciphertext.toByteArray()));
		}
	}

	@ParameterizedTest(name = "{0}: writing zero bytes creates the header")
	@EnumSource(CipherCombo.class)
	void testWriteNothing(CipherCombo combo) throws IOException {
		InMemoryCiphertext ciphertext = new InMemoryCiphertext();
		try (Cvf8Vault vault = vault(combo)) {
			try (VaultFile file = vault.createFile()) {
				Assertions.assertEquals(0, file.write(0, ByteBuffer.allocate(0), ciphertext, ciphertext));
				Assertions.assertEquals(0, file.size());
			}
			Assertions.assertEquals(vault.headerSize(), ciphertext.size());
			Assertions.assertArrayEquals(new byte[0], vault.decryptFile(ciphertext.toByteArray()));
		}
	}

	@ParameterizedTest(name = "{0}: truncate")
	@EnumSource(CipherCombo.class)
	void testTruncate(CipherCombo combo) throws IOException {
		byte[] cleartext = randomBytes(2 * CHUNK + 500, 4);
		try (Cvf8Vault vault = vault(combo)) {
			InMemoryCiphertext ciphertext = new InMemoryCiphertext(vault.encryptFile(cleartext));
			try (VaultFile file = vault.openFile(ByteBuffer.wrap(ciphertext.toByteArray(), 0, vault.headerSize()), ciphertext.size())) {
				Assertions.assertThrows(IllegalArgumentException.class, () -> file.truncate(file.size() + 1, ciphertext, ciphertext));

				// mid-chunk:
				file.truncate(CHUNK + 100, ciphertext, ciphertext);
				ciphertext.truncate(vault.ciphertextSize(CHUNK + 100));
				Assertions.assertEquals(CHUNK + 100, file.size());
				Assertions.assertArrayEquals(Arrays.copyOf(cleartext, CHUNK + 100), vault.decryptFile(ciphertext.toByteArray()));

				// exactly at chunk boundary:
				file.truncate(CHUNK, ciphertext, ciphertext);
				ciphertext.truncate(vault.ciphertextSize(CHUNK));
				Assertions.assertArrayEquals(Arrays.copyOf(cleartext, CHUNK), vault.decryptFile(ciphertext.toByteArray()));

				// to zero:
				file.truncate(0, ciphertext, ciphertext);
				ciphertext.truncate(vault.ciphertextSize(0));
				Assertions.assertEquals(0, file.size());
				Assertions.assertEquals(vault.headerSize(), ciphertext.size());
				Assertions.assertArrayEquals(new byte[0], vault.decryptFile(ciphertext.toByteArray()));

				// grow again:
				file.write(0, ByteBuffer.wrap(new byte[]{7}), ciphertext, ciphertext);
				Assertions.assertArrayEquals(new byte[]{7}, vault.decryptFile(ciphertext.toByteArray()));
			}
		}
	}

	@ParameterizedTest(name = "{0}: tampered chunk fails on read and on partial overwrite")
	@EnumSource(CipherCombo.class)
	void testTamperedChunk(CipherCombo combo) throws IOException {
		try (Cvf8Vault vault = vault(combo)) {
			InMemoryCiphertext ciphertext = new InMemoryCiphertext(vault.encryptFile(randomBytes(1000, 5)));
			ciphertext.flipBit(vault.headerSize() + 30);
			try (VaultFile file = vault.openFile(ByteBuffer.wrap(ciphertext.toByteArray(), 0, vault.headerSize()), ciphertext.size())) {
				Assertions.assertThrows(AuthenticationFailedException.class, () -> file.read(0, ByteBuffer.allocate(10), ciphertext));
				Assertions.assertThrows(AuthenticationFailedException.class, () -> file.write(5, ByteBuffer.allocate(10), ciphertext, ciphertext));
				// a full overwrite doesn't need to read the chunk:
				Assertions.assertDoesNotThrow(() -> file.write(0, ByteBuffer.allocate(1000), ciphertext, ciphertext));
				ByteBuffer dst = ByteBuffer.allocate(1000);
				Assertions.assertEquals(1000, file.read(0, dst, ciphertext));
				Assertions.assertArrayEquals(new byte[1000], dst.array());
			}
		}
	}

	@ParameterizedTest(name = "{0}: externally truncated ciphertext")
	@EnumSource(CipherCombo.class)
	void testExternallyTruncatedCiphertext(CipherCombo combo) throws IOException {
		try (Cvf8Vault vault = vault(combo)) {
			InMemoryCiphertext ciphertext = new InMemoryCiphertext(vault.encryptFile(randomBytes(1000, 6)));
			try (VaultFile file = vault.openFile(ByteBuffer.wrap(ciphertext.toByteArray(), 0, vault.headerSize()), ciphertext.size())) {
				ciphertext.truncate(ciphertext.size() - 10);
				Assertions.assertThrows(EOFException.class, () -> file.read(0, ByteBuffer.allocate(10), ciphertext));
			}
		}
	}

	private static byte[] randomBytes(int n, long seed) {
		byte[] result = new byte[n];
		new Random(seed).nextBytes(result);
		return result;
	}

}
