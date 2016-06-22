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
import java.util.concurrent.Executor;

import javax.crypto.SecretKey;

import org.cryptomator.cryptolib.rx.OnSubscribeReadableByteChannel;
import org.cryptomator.cryptolib.rx.Parallelizer;
import org.cryptomator.cryptolib.rx.WritableByteChannelEndpoint;

import rx.Observable;
import rx.Observable.OnSubscribe;
import rx.functions.Func1;
import rx.schedulers.Schedulers;

class FileContentDecryptor {

	private static final Executor EXECUTOR = CryptoExecutors.get();

	private final FileHeader header;
	private final SecretKey macKey;
	private final boolean authenticate;

	public FileContentDecryptor(FileHeader header, SecretKey macKey, boolean authenticate) {
		this.header = header;
		this.macKey = macKey;
		this.authenticate = authenticate;
	}

	public void decrypt(ReadableByteChannel ciphertextIn, WritableByteChannel cleartextOut, long firstChunkNumber) throws IOException {
		OnSubscribe<ByteBuffer> onSubscribeIn = new OnSubscribeReadableByteChannel(ciphertextIn, Constants.CHUNK_SIZE);
		Observable<ByteBuffer> observableIn = Observable.create(onSubscribeIn);
		Observable<Payload> observablePayloads = observableIn.map(new ByteBufferToPayloadMapper(firstChunkNumber));
		Observable<ByteBuffer> observableCleartext = Parallelizer.forObservable(observablePayloads).onScheduler(Schedulers.from(EXECUTOR)).map(new PayloadToCleartextMapper(), true);

		try {
			new WritableByteChannelEndpoint(cleartextOut, observableCleartext.subscribeOn(Schedulers.io())).awaitTermination(CryptoException.class);
		} catch (InterruptedException e) {
			IOException e2 = new InterruptedIOException();
			e2.initCause(e);
			throw e2;
		}
	}

	/**
	 * Transformation function, that calls the actual decryption routines.
	 */
	private class PayloadToCleartextMapper implements Func1<Payload, ByteBuffer> {

		@Override
		public ByteBuffer call(Payload payload) {
			final boolean isAuthentic = !authenticate || FileContentChunks.checkChunkMac(macKey, header.getNonce(), payload.getChunkNumber(), payload.getPayload());
			if (isAuthentic) {
				return FileContentChunks.decryptChunk(payload.getPayload(), header.getPayload().getContentKey());
			} else {
				throw new AuthenticationFailedException("Authentication of chunk " + payload.getChunkNumber() + " failed.");
			}
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
