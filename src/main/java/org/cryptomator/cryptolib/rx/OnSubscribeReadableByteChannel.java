/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.rx;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;

import rx.Observer;
import rx.observables.SyncOnSubscribe;

public final class OnSubscribeReadableByteChannel extends SyncOnSubscribe<ReadableByteChannel, ByteBuffer> {

	private final ReadableByteChannel channel;
	private final int bufferSize;

	public OnSubscribeReadableByteChannel(ReadableByteChannel channel, int bufferSize) {
		this.channel = channel;
		this.bufferSize = bufferSize;
	}

	@Override
	protected ReadableByteChannel generateState() {
		return this.channel;
	}

	@Override
	protected ReadableByteChannel next(ReadableByteChannel state, Observer<? super ByteBuffer> observer) {
		ByteBuffer buf = ByteBuffer.allocate(bufferSize);
		try {
			int count = state.read(buf);
			if (count == -1) {
				observer.onCompleted();
			} else {
				buf.flip();
				observer.onNext(buf);
			}
		} catch (IOException e) {
			observer.onError(e);
		}
		return state;
	}

}
