/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib;

import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

final class CryptoExecutors {

	private static final int NUM_THREADS = Runtime.getRuntime().availableProcessors();
	private static final String THREAD_NAME_PREFIX = "crypto-worker-";
	private static final Executor EXECUTOR = Executors.newFixedThreadPool(NUM_THREADS, new WorkerThreadFactory());

	public static Executor get() {
		return EXECUTOR;
	}

	private static class WorkerThreadFactory implements ThreadFactory {

		private final AtomicInteger counter = new AtomicInteger();
		private final ThreadFactory factory = Executors.defaultThreadFactory();

		@Override
		public Thread newThread(Runnable r) {
			Thread thread = factory.newThread(r);
			thread.setName(THREAD_NAME_PREFIX + counter.incrementAndGet());
			thread.setDaemon(true);
			return thread;
		}
	}

}
