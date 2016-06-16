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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.junit.Assert;
import org.junit.Test;

import rx.Observable;
import rx.functions.Func1;
import rx.schedulers.Schedulers;

public class ParallelizerTest {

	@Test
	public void testUnorderedParallelProcessing() throws InterruptedException {
		final List<Integer> numbers = Arrays.asList(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12);
		final ExecutorService exec = Executors.newFixedThreadPool(4);

		Observable<Integer> input = Observable.from(numbers);
		Observable<String> output = Parallelizer.forObservable(input).onScheduler(Schedulers.from(exec)).map(new Func1<Integer, String>() {

			@Override
			public String call(Integer num) {
				// this should (roughly) result in a reversed order:
				sleepQuietly(120 - num * 10, TimeUnit.MILLISECONDS);
				return Integer.toString(num);
			}

		});

		for (String str : output.toBlocking().toIterable()) {
			Assert.assertTrue(numbers.contains(Integer.parseInt(str)));
		}

		exec.shutdown();
	}

	@Test
	public void testFifoParallelProcessing() throws InterruptedException {
		final List<Integer> numbers = Arrays.asList(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12);
		final ExecutorService exec = Executors.newFixedThreadPool(4);

		Observable<Integer> input = Observable.from(numbers);
		Observable<String> output = Parallelizer.forObservable(input).onScheduler(Schedulers.from(exec)).map(new Func1<Integer, String>() {

			@Override
			public String call(Integer num) {
				// this should (roughly) result in a reversed order:
				sleepQuietly(120 - num * 10, TimeUnit.MILLISECONDS);
				return Integer.toString(num);
			}

		}, true);

		List<Integer> result = new ArrayList<>();
		for (String str : output.toBlocking().toIterable()) {
			result.add(Integer.parseInt(str));
		}

		Assert.assertArrayEquals(numbers.toArray(), result.toArray());

		exec.shutdown();
	}

	@Test(timeout = 1000)
	public void testTenThreadsSleepingAtTheSameTime() throws InterruptedException {
		final List<Integer> numbers = Arrays.asList(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
		final ExecutorService exec = Executors.newFixedThreadPool(10);

		Observable<Integer> input = Observable.from(numbers);
		Observable<Integer> output = Parallelizer.forObservable(input).onScheduler(Schedulers.from(exec)).map(new Func1<Integer, Integer>() {

			@Override
			public Integer call(Integer num) {
				sleepQuietly(501, TimeUnit.MILLISECONDS);
				return num;
			}

		}, true);

		List<Integer> result = new ArrayList<>();
		for (Integer num : output.toBlocking().toIterable()) {
			result.add(num);
		}

		Assert.assertArrayEquals(numbers.toArray(), result.toArray());

		exec.shutdown();
	}

	private static void sleepQuietly(int duration, TimeUnit unit) {
		try {
			Thread.sleep(unit.toMillis(duration));
		} catch (InterruptedException e) {

		}
	}

}
