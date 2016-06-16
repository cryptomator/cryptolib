/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.rx;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.junit.Assert;
import org.junit.Test;

import rx.Observable;
import rx.Scheduler;
import rx.functions.Func0;
import rx.functions.Func1;
import rx.schedulers.Schedulers;

public final class SequencerTest {

	private static Random RANDOM = new Random();

	@Test
	public void testSequencing() throws InterruptedException {
		final List<Integer> inputs = Arrays.asList(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12);
		final ExecutorService exec = Executors.newFixedThreadPool(4);

		Observable<Sequenced<Integer>> sequencedInput = Observable.from(inputs).map(Sequencer.<Integer>in());
		Observable<Sequenced<Integer>> sequencedOutput = mapInParallel(Schedulers.from(exec), sequencedInput, new Func1<Sequenced<Integer>, Observable<Sequenced<Integer>>>() {

			@Override
			public Observable<Sequenced<Integer>> call(Sequenced<Integer> input) {
				sleepQuietly(randomInt(50, 500), TimeUnit.MILLISECONDS);
				return Observable.just(input);
			}

		});
		Iterable<Integer> outputs = sequencedOutput.lift(Sequencer.<Integer>out()).toBlocking().toIterable();

		List<Integer> result = new ArrayList<>();
		for (Integer output : outputs) {
			result.add(output);
		}

		exec.shutdown();

		Assert.assertArrayEquals(inputs.toArray(), result.toArray());
	}

	public static Observable<Sequenced<Integer>> wasteTime(final Sequenced<Integer> input) {
		return Observable.defer(new Func0<Observable<Sequenced<Integer>>>() {

			@Override
			public Observable<Sequenced<Integer>> call() {
				sleepQuietly(randomInt(50, 500), TimeUnit.MILLISECONDS);
				return Observable.just(input);
			}
		});
	}

	public static <T> Observable<T> mapInParallel(final Scheduler scheduler, final Observable<T> observable, final Func1<T, Observable<T>> func) {
		return observable.flatMap(new Func1<T, Observable<T>>() {

			@Override
			public Observable<T> call(final T item) {
				return Observable.defer(new Func0<Observable<T>>() {

					@Override
					public Observable<T> call() {
						return func.call(item);
					}

				}).subscribeOn(scheduler);
			}

		});
	}

	private static int randomInt(int min, int max) {
		return RANDOM.nextInt((max - min) + 1) + min;
	}

	private static void sleepQuietly(int duration, TimeUnit unit) {
		try {
			Thread.sleep(unit.toMillis(duration));
		} catch (InterruptedException e) {

		}
	}

}
