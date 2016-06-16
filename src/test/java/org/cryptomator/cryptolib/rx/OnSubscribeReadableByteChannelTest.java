/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.rx;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;

import rx.Observable;
import rx.functions.Func1;

public class OnSubscribeReadableByteChannelTest {

	@Test
	public void testStreaming() {
		ReadableByteChannel ch = Channels.newChannel(new ByteArrayInputStream("hello world".getBytes(StandardCharsets.UTF_8)));

		Iterable<String> strs = Observable.create(new OnSubscribeReadableByteChannel(ch, 4)) //
				.map(new Func1<ByteBuffer, String>() {

					@Override
					public String call(ByteBuffer buf) {
						return StandardCharsets.UTF_8.decode(buf).toString();
					}
				}) //
				.toBlocking().toIterable();
		List<String> result = new ArrayList<>();
		for (String str : strs) {
			result.add(str);
		}
		Assert.assertArrayEquals(new String[] {"hell", "o wo", "rld"}, result.toArray());
	}

}
