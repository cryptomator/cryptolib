package org.cryptomator.cryptolib.common;

import com.google.common.base.Preconditions;

import javax.security.auth.Destroyable;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Objects;

public class ECKeyPair implements Destroyable {

	private final KeyPair keyPair;
	private boolean destroyed;

	ECKeyPair(KeyPair keyPair) {
		Preconditions.checkArgument(keyPair.getPrivate() instanceof ECPrivateKey);
		Preconditions.checkArgument(keyPair.getPublic() instanceof ECPublicKey);
		this.keyPair = keyPair;
	}

	public KeyPair keyPair() {
		return keyPair;
	}

	public ECPrivateKey getPrivate() {
		Preconditions.checkState(!destroyed);
		assert keyPair.getPrivate() instanceof ECPrivateKey;
		return (ECPrivateKey) keyPair.getPrivate();
	}

	public ECPublicKey getPublic() {
		Preconditions.checkState(!destroyed);
		assert keyPair.getPublic() instanceof ECPublicKey;
		return (ECPublicKey) keyPair.getPublic();
	}

	@Override
	public boolean isDestroyed() {
		return destroyed;
	}

	@Override
	public void destroy() {
		Destroyables.destroySilently(keyPair.getPrivate());
		destroyed = true;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		ECKeyPair that = (ECKeyPair) o;
		return MessageDigest.isEqual(this.getPublic().getEncoded(), that.getPublic().getEncoded());
	}

	@Override
	public int hashCode() {
		int result = Objects.hash(keyPair.getPublic().getAlgorithm());
		result = 31 * result + Arrays.hashCode(keyPair.getPublic().getEncoded());
		return result;
	}
}
