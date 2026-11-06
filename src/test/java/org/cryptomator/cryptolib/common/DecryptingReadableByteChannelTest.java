/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.common;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileContentCryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.util.Arrays;

import static java.nio.charset.StandardCharsets.UTF_8;

public class DecryptingReadableByteChannelTest {

	private Cryptor cryptor;
	private FileContentCryptor contentCryptor;
	private FileHeaderCryptor headerCryptor;
	private FileHeader header;

	@BeforeEach
	public void setup() throws AuthenticationFailedException {
		cryptor = Mockito.mock(Cryptor.class);
		contentCryptor = Mockito.mock(FileContentCryptor.class);
		headerCryptor = Mockito.mock(FileHeaderCryptor.class);
		header = Mockito.mock(FileHeader.class);
		Mockito.when(cryptor.fileContentCryptor()).thenReturn(contentCryptor);
		Mockito.when(cryptor.fileHeaderCryptor()).thenReturn(headerCryptor);
		Mockito.when(contentCryptor.ciphertextChunkSize()).thenReturn(10);
		Mockito.when(contentCryptor.cleartextChunkSize()).thenReturn(10);
		Mockito.when(headerCryptor.headerSize()).thenReturn(5);
		Mockito.doCallRealMethod().when(contentCryptor).cleartextSize(Mockito.anyLong()); // chunk sizes without overhead: cleartext size == ciphertext size
		Mockito.when(headerCryptor.decryptHeader(Mockito.any(ByteBuffer.class))).thenReturn(header);
		Mockito.when(contentCryptor.decryptChunk(Mockito.any(ByteBuffer.class), Mockito.anyLong(), Mockito.any(FileHeader.class), Mockito.anyBoolean())).thenAnswer(invocation -> {
			ByteBuffer input = invocation.getArgument(0);
			String inStr = UTF_8.decode(input).toString();
			return ByteBuffer.wrap(inStr.toLowerCase().getBytes(UTF_8));
		});
	}

	@Test
	public void testDecryption() throws IOException, AuthenticationFailedException {
		ReadableByteChannel src = Channels.newChannel(new ByteArrayInputStream("hhhhhTOPSECRET!TOPSECRET!".getBytes()));
		ByteBuffer result = ByteBuffer.allocate(30);
		try (DecryptingReadableByteChannel ch = new DecryptingReadableByteChannel(src, cryptor, true)) {
			int read1 = ch.read(result);
			Assertions.assertEquals(20, read1);
			int read2 = ch.read(result);
			Assertions.assertEquals(-1, read2);
			Assertions.assertArrayEquals("topsecret!topsecret!".getBytes(), Arrays.copyOfRange(result.array(), 0, read1));
		}
		Mockito.verify(contentCryptor).decryptChunk(Mockito.any(), Mockito.eq(0l), Mockito.eq(header), Mockito.eq(true));
		Mockito.verify(contentCryptor).decryptChunk(Mockito.any(), Mockito.eq(1l), Mockito.eq(header), Mockito.eq(true));
	}

	@Test
	public void testDecryptionOfStructurallyInvalidCiphertext() throws IOException {
		Mockito.doThrow(new IllegalArgumentException("e.g. missing EOF chunk")).when(contentCryptor).cleartextSize(20L);
		ReadableByteChannel src = Channels.newChannel(new ByteArrayInputStream("hhhhhTOPSECRET!TOPSECRET!".getBytes()));
		ByteBuffer result = ByteBuffer.allocate(30);
		try (DecryptingReadableByteChannel ch = new DecryptingReadableByteChannel(src, cryptor, true)) {
			IOException thrown = Assertions.assertThrows(IOException.class, () -> ch.read(result));
			MatcherAssert.assertThat(thrown.getCause(), CoreMatchers.instanceOf(AuthenticationFailedException.class));
		}
	}

	@Test
	public void testDecryptionWithInconsistentCleartextSize() throws IOException {
		Mockito.doReturn(19L).when(contentCryptor).cleartextSize(20L);
		ReadableByteChannel src = Channels.newChannel(new ByteArrayInputStream("hhhhhTOPSECRET!TOPSECRET!".getBytes()));
		ByteBuffer result = ByteBuffer.allocate(30);
		try (DecryptingReadableByteChannel ch = new DecryptingReadableByteChannel(src, cryptor, true)) {
			IOException thrown = Assertions.assertThrows(IOException.class, () -> ch.read(result));
			MatcherAssert.assertThat(thrown.getCause(), CoreMatchers.instanceOf(AuthenticationFailedException.class));
		}
	}

	@Test
	public void testDecryptionWithEmptyChunkInNonFinalPosition() throws IOException, AuthenticationFailedException {
		Mockito.doReturn(ByteBuffer.allocate(0)).when(contentCryptor).decryptChunk(Mockito.any(ByteBuffer.class), Mockito.eq(0L), Mockito.any(FileHeader.class), Mockito.anyBoolean());
		ReadableByteChannel src = Channels.newChannel(new ByteArrayInputStream("hhhhhTOPSECRET!TOPSECRET!".getBytes()));
		ByteBuffer result = ByteBuffer.allocate(30);
		try (DecryptingReadableByteChannel ch = new DecryptingReadableByteChannel(src, cryptor, true)) {
			IOException thrown = Assertions.assertThrows(IOException.class, () -> ch.read(result));
			MatcherAssert.assertThat(thrown.getCause(), CoreMatchers.instanceOf(AuthenticationFailedException.class));
		}
	}

	@Test
	public void testDecryptionWithEmptyFinalChunkUnknownToFormat() throws IOException, AuthenticationFailedException {
		Mockito.doReturn(ByteBuffer.allocate(0)).when(contentCryptor).decryptChunk(Mockito.any(ByteBuffer.class), Mockito.eq(1L), Mockito.any(FileHeader.class), Mockito.anyBoolean());
		Mockito.doThrow(new IllegalArgumentException("format does not know EOF chunks")).when(contentCryptor).cleartextSize(20L);
		Mockito.doReturn(10L).when(contentCryptor).cleartextSize(10L);
		ReadableByteChannel src = Channels.newChannel(new ByteArrayInputStream("hhhhhTOPSECRET!TOPSECRET!".getBytes()));
		ByteBuffer result = ByteBuffer.allocate(30);
		try (DecryptingReadableByteChannel ch = new DecryptingReadableByteChannel(src, cryptor, true)) {
			int read1 = ch.read(result);
			Assertions.assertEquals(10, read1);
			int read2 = ch.read(result);
			Assertions.assertEquals(-1, read2);
		}
	}

	@Test
	public void testDecryptionWithEmptyFinalChunk() throws IOException, AuthenticationFailedException {
		Mockito.doReturn(ByteBuffer.allocate(0)).when(contentCryptor).decryptChunk(Mockito.any(ByteBuffer.class), Mockito.eq(1L), Mockito.any(FileHeader.class), Mockito.anyBoolean());
		Mockito.doReturn(10L).when(contentCryptor).cleartextSize(20L);
		ReadableByteChannel src = Channels.newChannel(new ByteArrayInputStream("hhhhhTOPSECRET!TOPSECRET!".getBytes()));
		ByteBuffer result = ByteBuffer.allocate(30);
		try (DecryptingReadableByteChannel ch = new DecryptingReadableByteChannel(src, cryptor, true)) {
			int read1 = ch.read(result);
			Assertions.assertEquals(10, read1);
			int read2 = ch.read(result);
			Assertions.assertEquals(-1, read2);
		}
	}

	@Test
	public void testRandomAccessDecryption() throws IOException, AuthenticationFailedException {
		ReadableByteChannel src = Channels.newChannel(new ByteArrayInputStream("TOPSECRET!".getBytes()));
		ByteBuffer result = ByteBuffer.allocate(30);
		try (DecryptingReadableByteChannel ch = new DecryptingReadableByteChannel(src, cryptor, true, header, 1)) {
			int read1 = ch.read(result);
			Assertions.assertEquals(10, read1);
			int read2 = ch.read(result);
			Assertions.assertEquals(-1, read2);
			Assertions.assertArrayEquals("topsecret!".getBytes(), Arrays.copyOfRange(result.array(), 0, read1));
		}
		Mockito.verify(contentCryptor).decryptChunk(Mockito.any(), Mockito.eq(1l), Mockito.eq(header), Mockito.eq(true));
	}

}
