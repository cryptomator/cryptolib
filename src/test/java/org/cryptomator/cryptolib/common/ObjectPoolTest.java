package org.cryptomator.cryptolib.common;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.function.Supplier;

public class ObjectPoolTest {

	private Supplier<Foo> factory = Mockito.mock(Supplier.class);
	private ObjectPool<Foo> pool = new ObjectPool<>(factory);

	@BeforeEach
	public void setup() {
		Mockito.doAnswer(invocation -> new Foo()).when(factory).get();
	}

	@Test
	@DisplayName("new instance is created if pool is empty")
	public void testCreateNewObjWhenPoolIsEmpty() {
		try (ObjectPool.Lease<Foo> lease1 = pool.get()) {
			try (ObjectPool.Lease<Foo> lease2 = pool.get()) {
				Assertions.assertNotSame(lease1.get(), lease2.get());
			}
		}
		Mockito.verify(factory, Mockito.times(2)).get();
	}

	@Test
	@DisplayName("recycle existing instance")
	public void testRecycleExistingObj() {
		Foo foo1;
		try (ObjectPool.Lease<Foo> lease = pool.get()) {
			foo1 = lease.get();
		}
		try (ObjectPool.Lease<Foo> lease = pool.get()) {
			Assertions.assertSame(foo1, lease.get());
		}
		Mockito.verify(factory, Mockito.times(1)).get();
	}

	@Test
	@DisplayName("create new instance when pool is GC'ed")
	public void testGc() {
		try (ObjectPool.Lease<Foo> lease = pool.get()) {
			Assertions.assertNotNull(lease.get());
		}
		System.gc(); // seems to be reliable on Temurin 17 with @RepeatedTest(1000)
		try (ObjectPool.Lease<Foo> lease = pool.get()) {
			Assertions.assertNotNull(lease.get());
		}
		Mockito.verify(factory, Mockito.times(2)).get();
	}

	private static class Foo {
	}

}