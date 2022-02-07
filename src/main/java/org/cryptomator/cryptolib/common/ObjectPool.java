package org.cryptomator.cryptolib.common;

import java.lang.ref.WeakReference;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.function.Supplier;

/**
 * A simple object pool for resources that are expensive to create but are needed frequently.
 * <p>
 * Example Usage:
 * <pre>{@code
 *     Supplier<Foo> fooFactory = () -> new Foo();
 *     ObjectPool<Foo> fooPool = new ObjectPool(fooFactory);
 *     try (ObjectPool.Lease<Foo> lease = fooPool.get()) { // attempts to get a pooled Foo or invokes factory
 *         lease.get().foo(); // exclusively use Foo instance
 *     } // releases instance back to the pool when done
 * }</pre>
 *
 * @param <T> Type of the pooled objects
 */
public class ObjectPool<T> {

	private final Queue<WeakReference<T>> returnedInstances;
	private final Supplier<T> factory;

	public ObjectPool(Supplier<T> factory) {
		this.returnedInstances = new ConcurrentLinkedQueue<>();
		this.factory = factory;
	}

	public Lease<T> get() {
		WeakReference<T> ref;
		while ((ref = returnedInstances.poll()) != null) {
			T cached = ref.get();
			if (cached != null) {
				return new Lease<>(this, cached);
			}
		}
		return new Lease<>(this, factory.get());
	}

	/**
	 * A holder for resource leased from an {@link ObjectPool}.
	 * This is basically an {@link AutoCloseable autocloseable} {@link Supplier} that is intended to be used
	 * via try-with-resource blocks.
	 *
	 * @param <T> Type of the leased instance
	 */
	public static class Lease<T> implements AutoCloseable, Supplier<T> {

		private final ObjectPool<T> pool;
		private T obj;

		private Lease(ObjectPool<T> pool, T obj) {
			this.pool = pool;
			this.obj = obj;
		}

		public T get() {
			return obj;
		}

		@Override
		public void close() {
			pool.returnedInstances.add(new WeakReference<>(obj));
			obj = null;
		}
	}

}
