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

	/**
	 * Creates a new endpoint, that initializes a barrier on {@link Observable#doAfterTerminate(Action0) observable.doAfterTerminate(...)}.
	 * This barrier can be used do invoke {@link #awaitTermination(Class)} (preferrably on a different thread than what the observable
	 * will be {@link Observable#subscribeOn(rx.Scheduler) subscribed on}).
	 * 
	 * @param observable The observable to register the afterTerminate hook. This endpoint does not automatically subscribe to the observable. Please call {@link #subscribe()} explicitly.
	 * @see #awaitTermination(Class) Please read hint regarding potential deadlocks in awaitTermination(...).
	 */
	protected Endpoint(Observable<T> observable) {
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
		this.exception = e;
	}

	/**
	 * Waits until either completed or failed due to an error.<br>
	 * <b>Important:</b> This method causes deadlocks, when subscribed to an {@link Observable} on the same thread, that is calling this method.
	 * Please use {@link Observable#subscribeOn(rx.Scheduler)} to make sure, this will not happen.
	 * 
	 * @param <E> type of the expectedException
	 * @param expectedException The type of exception that can occur in this stream. Use any {@link RuntimeException}, if you don't expect exceptions.
	 * @throws InterruptedException If the caller is interrupted while waiting for this streams termination.
	 * @throws E If the expected exception has been thrown.
	 * @throws UnexpectedException If an unexpected exception has been thrown.
	 */
	public <E extends Throwable> void awaitTermination(Class<E> expectedException) throws InterruptedException, E, UnexpectedException {
		cdl.await();
		if (exception == null) {
			return; // :-)
		} else if (expectedException.isInstance(exception)) {
			try {
				@SuppressWarnings("unchecked")
				E e = (E) exception.getClass().newInstance();
				e.fillInStackTrace();
				e.initCause(exception);
				throw e;
			} catch (ReflectiveOperationException e) {
				throw expectedException.cast(exception);
			}
		} else {
			throw new UnexpectedException(exception);
		}
	}

	public static class UnexpectedException extends RuntimeException {
		private UnexpectedException(Throwable cause) {
			super("Unexpected exception.", cause);
		}
	}

}
