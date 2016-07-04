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
import java.util.concurrent.Callable;

import org.cryptomator.cryptolib.rx.Endpoint.UnexpectedException;
import org.hamcrest.CoreMatchers;
import org.junit.Rule;
import org.junit.Test;
import org.junit.internal.matchers.ThrowableMessageMatcher;
import org.junit.rules.ExpectedException;

import rx.Observable;

public class EndpointTest {

	@Rule
	public final ExpectedException thrown = ExpectedException.none();

	@Test
	public void testOnErrorWithExpectedException() throws InterruptedException, IOException {
		Observable<String> obs = Observable.fromCallable(new Callable<String>() {

			@Override
			public String call() throws Exception {
				throw new IOException("i am your father");
			}

		});
		Endpoint<String> testEndpoint = new TestEndpointImpl<>(obs);
		thrown.expect(IOException.class);
		thrown.expectCause(CoreMatchers.allOf(CoreMatchers.instanceOf(IOException.class), //
				ThrowableMessageMatcher.hasMessage(CoreMatchers.containsString("i am your father"))));
		testEndpoint.awaitTermination(IOException.class);
	}

	@Test
	public void testOnErrorWithExpectedExceptionWithoutDefaultConstructor() throws InterruptedException, ExceptionWithoutDefaultConstructor {
		Observable<String> obs = Observable.fromCallable(new Callable<String>() {

			@Override
			public String call() throws Exception {
				throw new ExceptionWithoutDefaultConstructor("i am your father");
			}

		});
		Endpoint<String> testEndpoint = new TestEndpointImpl<>(obs);
		thrown.expect(ExceptionWithoutDefaultConstructor.class);
		thrown.expectMessage("i am your father");
		thrown.expectCause(CoreMatchers.nullValue(Throwable.class));
		testEndpoint.awaitTermination(ExceptionWithoutDefaultConstructor.class);
	}

	@Test
	public void testOnErrorWithUnexpectedException() throws InterruptedException, IOException {
		Observable<String> obs = Observable.fromCallable(new Callable<String>() {

			@Override
			public String call() throws Exception {
				throw new IOException("i am your father");
			}

		});
		Endpoint<String> testEndpoint = new TestEndpointImpl<>(obs);
		thrown.expect(UnexpectedException.class);
		thrown.expectCause(CoreMatchers.allOf(CoreMatchers.instanceOf(IOException.class), //
				ThrowableMessageMatcher.hasMessage(CoreMatchers.containsString("i am your father"))));
		testEndpoint.awaitTermination(IndexOutOfBoundsException.class);
	}

	private static class ExceptionWithoutDefaultConstructor extends Exception {
		public ExceptionWithoutDefaultConstructor(String msg) {
			super(msg);
		}
	}

	private static class TestEndpointImpl<T> extends Endpoint<T> {

		public TestEndpointImpl(Observable<T> observable) {
			super(observable);
			subscribe();
		}

		@Override
		public void onCompleted() {
			// no-op
		}

		@Override
		public void onNext(T t) {
			// no-op
		}

	}

}
