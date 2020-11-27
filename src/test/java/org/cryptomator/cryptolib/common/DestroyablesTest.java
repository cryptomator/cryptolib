package org.cryptomator.cryptolib.common;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

public class DestroyablesTest {

	@Test
	public void testDestroySilently() throws DestroyFailedException {
		Destroyable destroyable = Mockito.mock(Destroyable.class);

		Destroyables.destroySilently(destroyable);

		Mockito.verify(destroyable).destroy();
	}

	@Test
	public void testDestroySilentlyIgnoresNull() {
		Destroyables.destroySilently(null);
	}

	@Test
	public void testDestroySilentlySuppressesException() throws DestroyFailedException {
		Destroyable destroyable = Mockito.mock(Destroyable.class);
		Mockito.doThrow(new DestroyFailedException()).when(destroyable).destroy();

		Destroyables.destroySilently(destroyable);

		Mockito.verify(destroyable).destroy();
	}

}