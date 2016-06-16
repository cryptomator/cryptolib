/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.rx;

import java.util.SortedMap;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicLong;

import rx.Observable.Operator;
import rx.Subscriber;
import rx.functions.Func1;

/**
 * Utility to ensure FiFo order of streamed items.
 */
public final class Sequencer {

	static <U> FirstIn<U> in() {
		return new FirstIn<U>();
	}

	static <U> FirstOut<U> out() {
		return new FirstOut<U>();
	}

	static <T, R> Func1<Sequenced<T>, Sequenced<R>> wrap(final Func1<T, R> func) {
		return new Func1Wrapper<T, R>(func);
	}

	private static class FirstIn<T> implements Func1<T, Sequenced<T>> {

		private final AtomicLong inSeq = new AtomicLong();

		@Override
		public Sequenced<T> call(T item) {
			return new SequencedImpl<T>(inSeq.getAndIncrement(), item);
		}

	}

	private static class FirstOut<T> implements Operator<T, Sequenced<T>> {

		private final AtomicLong outSeq = new AtomicLong();
		private final SortedMap<Long, T> buffer = new TreeMap<>();

		@Override
		public Subscriber<? super Sequenced<T>> call(Subscriber<? super T> subscriber) {
			return new SequencedSubscriber(subscriber);
		}

		private class SequencedSubscriber extends Subscriber<Sequenced<T>> {

			private final Subscriber<? super T> subscriber;

			public SequencedSubscriber(Subscriber<? super T> subscriber) {
				this.subscriber = subscriber;
			}

			@Override
			public void onCompleted() {
				if (!subscriber.isUnsubscribed()) {
					tryFlushBuffer();
					subscriber.onCompleted();
				}
			}

			@Override
			public void onError(Throwable e) {
				if (!subscriber.isUnsubscribed()) {
					subscriber.onError(e);
				}
			}

			@Override
			public void onNext(Sequenced<T> item) {
				if (!subscriber.isUnsubscribed()) {
					Long seq = item.getSeq();
					if (outSeq.compareAndSet(seq, seq + 1)) {
						subscriber.onNext(item.getItem());
					} else {
						buffer.put(seq, item.getItem());
					}
					tryFlushBuffer();
				}
			}

			private void tryFlushBuffer() {
				long seq = outSeq.get();
				while (buffer.containsKey(seq)) {
					T item = buffer.remove(seq);
					outSeq.compareAndSet(seq, ++seq);
					subscriber.onNext(item);
				}
			}

		}
	}

	private static class SequencedImpl<T> implements Sequenced<T> {

		private final long seq;
		private final T item;

		public SequencedImpl(long seq, T item) {
			this.seq = seq;
			this.item = item;
		}

		@Override
		public T getItem() {
			return item;
		}

		@Override
		public long getSeq() {
			return seq;
		}
	}

	private static class Func1Wrapper<T, R> implements Func1<Sequenced<T>, Sequenced<R>> {

		private final Func1<T, R> func;

		public Func1Wrapper(Func1<T, R> func) {
			this.func = func;
		}

		@Override
		public Sequenced<R> call(Sequenced<T> t) {
			final R result = func.call(t.getItem());
			return new SequencedImpl<R>(t.getSeq(), result);
		}

	}

}
