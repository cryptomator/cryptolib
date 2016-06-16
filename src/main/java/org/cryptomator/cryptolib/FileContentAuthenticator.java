/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib;

import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.util.concurrent.Executor;

import javax.crypto.SecretKey;

import org.cryptomator.cryptolib.rx.OnSubscribeReadableByteChannel;
import org.cryptomator.cryptolib.rx.Parallelizer;

import rx.Observable;
import rx.Observable.OnSubscribe;
import rx.functions.Func1;
import rx.schedulers.Schedulers;

/**
 * Performs authentication over multiple chunks, but does not decrypt anything.
 */
public class FileContentAuthenticator {

	private static final Executor EXECUTOR = CryptoExecutors.get();

	private final FileHeader header;
	private final SecretKey macKey;

	public FileContentAuthenticator(FileHeader header, SecretKey macKey) {
		this.header = header;
		this.macKey = macKey;
	}

	public boolean authenticate(ReadableByteChannel ciphertextIn, long firstChunkNumber) {
		OnSubscribe<ByteBuffer> onSubscribeIn = new OnSubscribeReadableByteChannel(ciphertextIn, Constants.CHUNK_SIZE);
		Observable<ByteBuffer> observableIn = Observable.create(onSubscribeIn);
		Observable<Payload> observablePayloads = observableIn.map(new ByteBufferToPayloadMapper(firstChunkNumber));
		// return observablePayloads.all(new PayloadToAuthResultMapper()).toBlocking().first();
		Observable<Boolean> observableAuthResults = Parallelizer.forObservable(observablePayloads).onScheduler(Schedulers.from(EXECUTOR)).map(new PayloadToAuthResultMapper());
		return observableAuthResults.onBackpressureBuffer(100).all(new TrueFilter()).toBlocking().first();
	}

	/**
	 * Transformation function, that calls the actual authentication routines.
	 */
	private class PayloadToAuthResultMapper implements Func1<Payload, Boolean> {

		@Override
		public Boolean call(Payload payload) {
			return FileContentChunks.checkChunkMac(macKey, header.getNonce(), payload.getChunkNumber(), payload.getPayload());
		}

	}

	/**
	 * 
	 */
	private class TrueFilter implements Func1<Boolean, Boolean> {

		@Override
		public Boolean call(Boolean t) {
			return t;
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
