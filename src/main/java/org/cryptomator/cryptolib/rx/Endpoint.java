/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.rx;

import java.util.concurrent.CountDownLatch;

import rx.Observable;
import rx.Subscriber;
import rx.functions.Action0;

public abstract class Endpoint<T> extends Subscriber<T> {

	private final CountDownLatch cdl = new CountDownLatch(1);
	private volatile Throwable exception = null;
	private final Countdown countdown = new Countdown();
	protected final Observable<T> observable;

	public Endpoint(Observable<T> observable) {
		this.observable = observable.doAfterTerminate(countdown);
	}

	/**
	 * Subscribes to the {@link #observable}.
	 * Make sure, this method is not called, before the Endpoint is fully initialized. Otherwise race conditions may occur.
	 */
	protected void subscribe() {
		observable.subscribe(this);
	}

	private class Countdown implements Action0 {

		@Override
		public void call() {
			cdl.countDown();
		}

	}

	@Override
	public final void onError(Throwable e) {
		e.printStackTrace();
		this.exception = e;
	}

	/**
	 * Waits until either completed or failed due to an error.<br/>
	 * <b>Important:</b> This method causes deadlocks, when subscribed to an {@link Observable} on the same thread, that is calling this method.
	 * Please use {@link Observable#subscribeOn(rx.Scheduler)} to make sure, this will not happen.
	 * 
	 * @param expectedException The type of exception that can occur in this stream.
	 * @throws InterruptedException If the caller is interrupted while waiting for this streams termination.
	 * @throws E If the expected exception has been thrown.
	 * @throws RuntimeException If an unexpected exception has been thrown.
	 */
	public <E extends Throwable> void waitForTermination(Class<E> expectedException) throws InterruptedException, E, RuntimeException {
		cdl.await();
		if (exception == null) {
			// :-)
		} else if (expectedException.isInstance(exception)) {
			throw expectedException.cast(exception);
		} else {
			throw new RuntimeException("Unexpected exception.", exception);
		}
	}

}
