package org.cryptomator.cryptolib.common;

import java.lang.ref.WeakReference;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.function.Supplier;

public class ObjectPool<T> {

	private final Queue<WeakReference<T>> pool;
	private final Supplier<T> factory;

	public ObjectPool(Supplier<T> factory) {
		this.pool = new ConcurrentLinkedQueue<>();
		this.factory = factory;
	}

	public Lease get() {
		WeakReference<T> ref;
		while ((ref = pool.poll()) != null) {
			T cached = ref.get();
			if (cached != null) {
				return new Lease(cached);
			}
		}
		return new Lease(factory.get());
	}

	public class Lease implements AutoCloseable {

		private T obj;

		public Lease(T obj) {
			this.obj = obj;
		}

		public T get() {
			return obj;
		}

		@Override
		public void close() {
			pool.offer(new WeakReference<>(obj));
			obj = null;
		}
	}

}
