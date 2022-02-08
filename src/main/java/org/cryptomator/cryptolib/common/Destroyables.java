package org.cryptomator.cryptolib.common;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

public class Destroyables {

	private Destroyables() {
	}

	public static void destroySilently(Destroyable destroyable) {
		if (destroyable == null) {
			return;
		}
		try {
			destroyable.destroy();
		} catch (DestroyFailedException e) {
			// no-op
		}
	}

}
