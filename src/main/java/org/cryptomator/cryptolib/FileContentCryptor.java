/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.security.SecureRandom;

import javax.crypto.SecretKey;

public class FileContentCryptor {

	private final SecretKey macKey;
	private final SecureRandom random;
	private final FileHeaderCryptor fileHeaderCryptor;

	/**
	 * Package-private constructor.
	 * Use {@link Cryptor#fileContentCryptor()} to obtain a FileContentCryptor instance.
	 */
	FileContentCryptor(SecretKey macKey, SecureRandom random, FileHeaderCryptor fileHeaderCryptor) {
		this.macKey = macKey;
		this.random = random;
		this.fileHeaderCryptor = fileHeaderCryptor;
	}

	/**
	 * Encrypts a single chunk of cleartext.
	 * 
	 * @param cleartextChunk Content to be encrypted
	 * @param chunkNumber Number of the chunk to be encrypted
	 * @param header Header of the file, this chunk belongs to
	 * @return Encrypted content.
	 */
	public ByteBuffer encryptChunk(ByteBuffer cleartextChunk, long chunkNumber, FileHeader header) {
		if (cleartextChunk.remaining() == 0 || cleartextChunk.remaining() > Constants.PAYLOAD_SIZE) {
			throw new IllegalArgumentException("Invalid chunk");
		}
		return FileContentChunks.encryptChunk(cleartextChunk.asReadOnlyBuffer(), chunkNumber, header.getNonce(), header.getPayload().getContentKey(), macKey, random);
	}

	/**
	 * Encrypts all contents, that can be read from <code>cleartext</code> and writes them to <code>ciphertext</code>.
	 * This method blocks until all content has been encrypted.
	 * 
	 * @param cleartext Input before encryption
	 * @param ciphertext Encrypted output
	 * @throws IOException In case of exceptions that occur during read/write from the given channels.
	 */
	public void encryptFile(ReadableByteChannel cleartext, SeekableByteChannel ciphertext) throws IOException {
		FileHeader header = fileHeaderCryptor.create();
		try {
			ByteBuffer headerBuf = fileHeaderCryptor.encryptHeader(header);
			ciphertext.truncate(0);
			ciphertext.write(headerBuf);
			FileContentEncryptor encryptor = new FileContentEncryptor(header, macKey, random);
			CountingReadableByteChannel counting = new GarbageAppendingReadableByteChannel(cleartext, random);
			encryptor.encrypt(counting, ciphertext, 0);
			ciphertext.position(0);
			header.getPayload().setFilesize(counting.getNumberOfBytesRead());
			headerBuf = fileHeaderCryptor.encryptHeader(header);
			ciphertext.write(headerBuf);
		} finally {
			header.destroy();
		}
	}

	/**
	 * Decrypts a single chunk of ciphertext.
	 * 
	 * @param ciphertextChunk Content to be decrypted
	 * @param chunkNumber Number of the chunk to be decrypted
	 * @param header Header of the file, this chunk belongs to
	 * @param authenticate Skip authentication by setting this flag to <code>false</code>. Should always be <code>true</code> by default.
	 * @return Decrypted content.
	 * @throws AuthenticationFailedException If authenticate is <code>true</code> and the given chunk does not match its MAC.
	 */
	public ByteBuffer decryptChunk(ByteBuffer ciphertextChunk, long chunkNumber, FileHeader header, boolean authenticate) throws AuthenticationFailedException {
		if (ciphertextChunk.remaining() == 0 || ciphertextChunk.remaining() > Constants.CHUNK_SIZE) {
			throw new IllegalArgumentException("Invalid chunk");
		}
		if (!authenticate || FileContentChunks.checkChunkMac(macKey, header.getNonce(), chunkNumber, ciphertextChunk.asReadOnlyBuffer())) {
			return FileContentChunks.decryptChunk(ciphertextChunk.asReadOnlyBuffer(), header.getPayload().getContentKey());
		} else {
			throw new AuthenticationFailedException("Authentication of chunk " + chunkNumber + " failed.");
		}
	}

	/**
	 * Decrypts all contents, that can be read from <code>ciphertext</code> and writes them to <code>cleartext</code>.
	 * This method blocks until all content has been decrypted.
	 * 
	 * @param ciphertext Input before decryption
	 * @param cleartext Decrypted output
	 * @param authenticate Skip authentication by setting this flag to <code>false</code>. Should always be <code>true</code> by default.
	 * @throws IOException In case of exceptions that occur during read/write from the given channels.
	 */
	public void decryptFile(ReadableByteChannel ciphertext, WritableByteChannel cleartext, boolean authenticate) throws IOException {
		ByteBuffer headerBuf = ByteBuffer.allocate(FileHeader.SIZE);
		int read = ciphertext.read(headerBuf);
		if (read != FileHeader.SIZE) {
			throw new IllegalArgumentException("Ciphertext shorter than header size.");
		}
		headerBuf.flip();
		FileHeader header = fileHeaderCryptor.decryptHeader(headerBuf);
		try {
			long cleartextSize = header.getPayload().getFilesize();
			long numChunks = 1 + cleartextSize / Constants.PAYLOAD_SIZE;
			long ciphertextSize = numChunks * Constants.CHUNK_SIZE;
			ReadableByteChannel limitingIn = new LimitingReadableByteChannel(ciphertext, ciphertextSize);
			WritableByteChannel limitingOut = new LimitingWritableByteChannel(cleartext, cleartextSize);
			FileContentDecryptor decryptor = new FileContentDecryptor(header, macKey, authenticate);
			decryptor.decrypt(limitingIn, limitingOut, 0);
		} finally {
			header.destroy();
		}
	}

}
