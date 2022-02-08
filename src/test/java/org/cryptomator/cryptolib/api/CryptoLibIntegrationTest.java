/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.api;

import org.cryptomator.cryptolib.common.DecryptingReadableByteChannel;
import org.cryptomator.cryptolib.common.EncryptingWritableByteChannel;
import org.cryptomator.cryptolib.common.SecureRandomMock;
import org.cryptomator.cryptolib.common.SeekableByteChannelMock;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.stream.Stream;

public class CryptoLibIntegrationTest {

	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.PRNG_RANDOM;

	private static Stream<Cryptor> getCryptors() {
		return Stream.of(
				CryptorProvider.forScheme(CryptorProvider.Scheme.SIV_CTRMAC).provide(Masterkey.generate(RANDOM_MOCK), RANDOM_MOCK),
				CryptorProvider.forScheme(CryptorProvider.Scheme.SIV_GCM).provide(Masterkey.generate(RANDOM_MOCK), RANDOM_MOCK)
		);
	}

	@ParameterizedTest
	@MethodSource("getCryptors")
	public void testDecryptEncrypted(Cryptor cryptor) throws IOException {
		int size = 1 * 1024 * 1024;
		ByteBuffer ciphertextBuffer = ByteBuffer.allocate(2 * size);

		ByteBuffer cleartext = ByteBuffer.allocate(size);
		try (WritableByteChannel ch = new EncryptingWritableByteChannel(new SeekableByteChannelMock(ciphertextBuffer), cryptor)) {
			int written = ch.write(cleartext);
			Assertions.assertEquals(size, written);
		}

		ciphertextBuffer.flip();

		ByteBuffer result = ByteBuffer.allocate(size + 1);
		try (ReadableByteChannel ch = new DecryptingReadableByteChannel(new SeekableByteChannelMock(ciphertextBuffer), cryptor, true)) {
			int read = ch.read(result);
			Assertions.assertEquals(size, read);
		}

		Assertions.assertArrayEquals(cleartext.array(), Arrays.copyOfRange(result.array(), 0, size));
	}

	@ParameterizedTest
	@MethodSource("getCryptors")
	public void testDecryptManipulatedEncrypted(Cryptor cryptor) throws IOException {
		int size = 1 * 1024 * 1024;
		ByteBuffer ciphertextBuffer = ByteBuffer.allocate(2 * size);

		ByteBuffer cleartext = ByteBuffer.allocate(size);
		try (WritableByteChannel ch = new EncryptingWritableByteChannel(new SeekableByteChannelMock(ciphertextBuffer), cryptor)) {
			int written = ch.write(cleartext);
			Assertions.assertEquals(size, written);
		}

		ciphertextBuffer.position(0);
		int firstByteOfFirstChunk = cryptor.fileHeaderCryptor().headerSize() + 1; // not inside chunk MAC
		ciphertextBuffer.put(firstByteOfFirstChunk, (byte) ~ciphertextBuffer.get(firstByteOfFirstChunk));

		ByteBuffer result = ByteBuffer.allocate(size + 1);
		try (ReadableByteChannel ch = new DecryptingReadableByteChannel(new SeekableByteChannelMock(ciphertextBuffer), cryptor, true)) {
			IOException thrown = Assertions.assertThrows(IOException.class, () -> {
				ch.read(result);
			});
			MatcherAssert.assertThat(thrown.getCause(), CoreMatchers.instanceOf(AuthenticationFailedException.class));
		}
	}

	@ParameterizedTest
	@MethodSource("getCryptors")
	public void testDecryptManipulatedEncryptedSkipAuth(Cryptor cryptor) throws IOException {
		Assumptions.assumeTrue(cryptor.fileContentCryptor().canSkipAuthentication(), "cryptor doesn't support decryption of unauthentic ciphertext");
		int size = 1 * 1024 * 1024;
		ByteBuffer ciphertextBuffer = ByteBuffer.allocate(2 * size);

		ByteBuffer cleartext = ByteBuffer.allocate(size);
		try (WritableByteChannel ch = new EncryptingWritableByteChannel(new SeekableByteChannelMock(ciphertextBuffer), cryptor)) {
			int written = ch.write(cleartext);
			Assertions.assertEquals(size, written);
		}

		ciphertextBuffer.flip();
		int lastByteOfFirstChunk = cryptor.fileHeaderCryptor().headerSize() + cryptor.fileContentCryptor().ciphertextChunkSize() - 1; // inside chunk MAC
		ciphertextBuffer.put(lastByteOfFirstChunk, (byte) ~ciphertextBuffer.get(lastByteOfFirstChunk));

		ByteBuffer result = ByteBuffer.allocate(size + 1);
		try (ReadableByteChannel ch = new DecryptingReadableByteChannel(new SeekableByteChannelMock(ciphertextBuffer), cryptor, false)) {
			int read = ch.read(result);
			Assertions.assertEquals(size, read);
		}

		Assertions.assertArrayEquals(cleartext.array(), Arrays.copyOfRange(result.array(), 0, size));
	}

}
