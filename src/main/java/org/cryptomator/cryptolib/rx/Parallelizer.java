/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.rx;

import rx.Observable;
import rx.Scheduler;
import rx.functions.Func0;
import rx.functions.Func1;

/**
 * Allows parallel processing in the {@link #map(Func1)} function.
 */
public class Parallelizer<T> {

	private final Scheduler scheduler;
	private final Observable<T> observable;

	/* Construction */

	public static <T> ParallelizerBuilder<T> forObservable(Observable<T> observable) {
		return new ParallelizerBuilder<>(observable);
	}

	public static class ParallelizerBuilder<T> {

		private final Observable<T> observable;

		private ParallelizerBuilder(Observable<T> observable) {
			this.observable = observable;
		}

		public Parallelizer<T> onScheduler(Scheduler scheduler) {
			return new Parallelizer<>(scheduler, observable);
		}

	}

	private Parallelizer(Scheduler scheduler, Observable<T> observable) {
		this.scheduler = scheduler;
		this.observable = observable;
	}

	/* Mapping */

	public <R> Observable<R> map(final Func1<T, R> func) {
		return map(func, false);
	}

	public <R> Observable<R> map(final Func1<T, R> func, boolean fifo) {
		if (fifo) {
			Func1<Sequenced<T>, Sequenced<R>> sequencedFunc = Sequencer.wrap(func);
			Observable<Sequenced<T>> sequencedIn = observable.map(Sequencer.<T>in());
			Observable<Sequenced<R>> sequencedOut = sequencedIn.flatMap(new DeferredScheduledMapper<>(sequencedFunc, scheduler));
			return sequencedOut.lift(Sequencer.<R>out());
		} else {
			return observable.flatMap(new DeferredScheduledMapper<T, R>(func, scheduler));
		}
	}

	/**
	 * Defers the mapping function and invokes it on a specific Scheduler.
	 */
	private static class DeferredScheduledMapper<T, R> implements Func1<T, Observable<R>> {

		private final Func1<T, R> func;
		private final Scheduler scheduler;

		public DeferredScheduledMapper(Func1<T, R> func, Scheduler scheduler) {
			this.func = func;
			this.scheduler = scheduler;
		}

		@Override
		public Observable<R> call(T item) {
			return Observable.defer(new MappedObservableFactory<T, R>(func, item)).subscribeOn(scheduler);
		}

	}

	/**
	 * Invokes the mapping function and returns the result as an Observable.
	 */
	private static class MappedObservableFactory<T, R> implements Func0<Observable<R>> {

		private final Func1<T, R> func;
		private final T item;

		public MappedObservableFactory(Func1<T, R> func, T item) {
			this.func = func;
			this.item = item;
		}

		@Override
		public Observable<R> call() {
			return Observable.just(item).map(func);
		}

	}

}
