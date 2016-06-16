/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.rx;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.WritableByteChannel;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.Assert;
import org.junit.Test;

import rx.Observable;
import rx.functions.Func1;
import rx.schedulers.Schedulers;

public class WritableByteChannelEndpointTest {

	@Test
	public void testStreaming() throws InterruptedException, IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		WritableByteChannel ch = Channels.newChannel(baos);

		Observable<ByteBuffer> observable = Observable.from(Arrays.asList("hello", " world")).map(new Func1<String, ByteBuffer>() {
			@Override
			public ByteBuffer call(String str) {
				return ByteBuffer.wrap(str.getBytes(StandardCharsets.UTF_8));
			}
		}).subscribeOn(Schedulers.newThread());

		new WritableByteChannelEndpoint(ch, observable).waitForTermination(IOException.class);

		Assert.assertArrayEquals("hello world".getBytes(StandardCharsets.UTF_8), baos.toByteArray());
	}

}
