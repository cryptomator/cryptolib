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
import java.io.InterruptedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.security.SecureRandom;
import java.util.concurrent.Executor;

import javax.crypto.SecretKey;

import org.cryptomator.cryptolib.rx.OnSubscribeReadableByteChannel;
import org.cryptomator.cryptolib.rx.Parallelizer;
import org.cryptomator.cryptolib.rx.WritableByteChannelEndpoint;

import rx.Observable;
import rx.Observable.OnSubscribe;
import rx.functions.Func1;
import rx.schedulers.Schedulers;

class FileContentEncryptor {

	private static final Executor EXECUTOR = CryptoExecutors.get();

	private final FileHeader header;
	private final SecretKey macKey;
	private final SecureRandom random;

	public FileContentEncryptor(FileHeader header, SecretKey macKey, SecureRandom random) {
		this.header = header;
		this.macKey = macKey;
		this.random = random;
	}

	/**
	 * @param cleartextIn channel skipped exactly to the position of the first chunk.
	 * @param ciphertextOut channel to which ciphertext is written.
	 * @param firstChunkNumber number of the first chunk. Must be aligned with the position of cleartextIn.
	 * @throws IOException
	 */
	public void encrypt(ReadableByteChannel cleartextIn, WritableByteChannel ciphertextOut, long firstChunkNumber) throws IOException {
		OnSubscribe<ByteBuffer> onSubscribeIn = new OnSubscribeReadableByteChannel(cleartextIn, Constants.PAYLOAD_SIZE);
		Observable<ByteBuffer> observableIn = Observable.create(onSubscribeIn);
		Observable<Payload> observablePayloads = observableIn.map(new ByteBufferToPayloadMapper(firstChunkNumber));
		Observable<ByteBuffer> observableCiphertext = Parallelizer.forObservable(observablePayloads).onScheduler(Schedulers.from(EXECUTOR)).map(new PayloadToCiphertextMapper(), true);

		try {
			new WritableByteChannelEndpoint(ciphertextOut, observableCiphertext.subscribeOn(Schedulers.io())).waitForTermination(IOException.class);
		} catch (InterruptedException e) {
			IOException e2 = new InterruptedIOException();
			e2.initCause(e);
			throw e2;
		}
	}

	/**
	 * Transformation function, that calls the actual encryption routines.
	 */
	private class PayloadToCiphertextMapper implements Func1<Payload, ByteBuffer> {

		@Override
		public ByteBuffer call(Payload payload) {
			return FileContentChunks.encryptChunk(payload.getPayload(), payload.getChunkNumber(), header.getNonce(), header.getPayload().getContentKey(), macKey, random);
		}

	}

	/**
	 * Transformation function, that wraps ByteBuffers into {@link Payload Payloads}.
	 */
	private static class ByteBufferToPayloadMapper implements Func1<ByteBuffer, Payload> {

		private long chunkNumber;

		public ByteBufferToPayloadMapper(long firstChunkNumber) {
			this.chunkNumber = firstChunkNumber;
		}

		@Override
		public Payload call(ByteBuffer payload) {
			return new Payload(payload, chunkNumber++);
		}

	}

	/**
	 * Payloads wrap ByteBuffers, that are given a specific chunk number.
	 */
	private static class Payload {

		private final ByteBuffer payload;
		private final long chunkNumber;

		public Payload(ByteBuffer payload, long chunkNumber) {
			this.payload = payload;
			this.chunkNumber = chunkNumber;
		}

		public ByteBuffer getPayload() {
			return payload;
		}

		public long getChunkNumber() {
			return chunkNumber;
		}

	}

}
