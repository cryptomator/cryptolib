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
import java.nio.channels.WritableByteChannel;
import java.util.Objects;

import rx.Observable;

public class WritableByteChannelEndpoint extends Endpoint<ByteBuffer> {

	private final WritableByteChannel channel;

	public WritableByteChannelEndpoint(WritableByteChannel channel, Observable<ByteBuffer> observable) {
		super(observable);
		this.channel = Objects.requireNonNull(channel);
		this.subscribe();
	}

	@Override
	public void onCompleted() {
		// no-op
	}

	@Override
	public void onNext(ByteBuffer input) {
		try {
			if (channel.isOpen()) {
				channel.write(input);
			}
		} catch (IOException e) {
			this.onError(e);
		}
	}

}
