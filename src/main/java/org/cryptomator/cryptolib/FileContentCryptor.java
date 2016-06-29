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

	private final SecretKey headerKey;
	private final SecretKey macKey;
	private final SecureRandom random;

	/**
	 * Package-private constructor.
	 * Use {@link Cryptor#fileContentCryptor()} to obtain a FileContentCryptor instance.
	 */
	FileContentCryptor(SecretKey encryptionKey, SecretKey macKey, SecureRandom random) {
		this.headerKey = encryptionKey;
		this.macKey = macKey;
		this.random = random;
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
		FileHeader header = FileHeaders.create(random);
		try {
			ByteBuffer headerBuf = FileHeaders.encryptHeader(header, headerKey, macKey);
			ciphertext.truncate(0);
			ciphertext.write(headerBuf);
			FileContentEncryptor encryptor = new FileContentEncryptor(header, macKey, random);
			CountingReadableByteChannel counting = new GarbageAppendingReadableByteChannel(cleartext, random);
			encryptor.encrypt(counting, ciphertext, 0);
			ciphertext.position(0);
			header.getPayload().setFilesize(counting.getNumberOfBytesRead());
			headerBuf = FileHeaders.encryptHeader(header, headerKey, macKey);
			ciphertext.write(headerBuf);
		} finally {
			header.destroy();
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
		FileHeader header = FileHeaders.decryptHeader(headerBuf, headerKey, macKey);
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
