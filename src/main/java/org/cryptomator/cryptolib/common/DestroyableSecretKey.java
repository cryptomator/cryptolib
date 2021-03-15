package org.cryptomator.cryptolib.common;

import com.google.common.base.Preconditions;

import javax.crypto.SecretKey;
import javax.security.auth.Destroyable;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/**
 * A {@link SecretKey} that (<a href="https://bugs.openjdk.java.net/browse/JDK-8160206">other than JDK's SecretKeySpec</a>)
 * actually implements {@link Destroyable}.
 * <p>
 * Furthermore this key keeps track of any accesses via {@link #getEncoded()} and will destroy returned byte arrays as well.
 */
public class DestroyableSecretKey implements SecretKey, AutoCloseable {

	private transient final byte[] key;
	private final String algorithm;
	private boolean destroyed;

	public DestroyableSecretKey(byte[] key, String algorithm) {
		this(key, 0, key.length, algorithm);
	}

	public DestroyableSecretKey(byte[] key, int offset, int len, String algorithm) {
		Preconditions.checkArgument(offset >= 0, "Invalid offset");
		Preconditions.checkArgument(len >= 0, "Invalid length");
		Preconditions.checkArgument(key.length >= offset+len, "Invalid offset/len");
		this.key = new byte[len];
		this.algorithm = Preconditions.checkNotNull(algorithm, "Algorithm must not be null");
		this.destroyed = false;
		System.arraycopy(key, offset, this.key, 0, len);
	}

	public static DestroyableSecretKey from(SecretKey secretKey) {
		if (secretKey instanceof DestroyableSecretKey) {
			return (DestroyableSecretKey) secretKey;
		} else {
			return new DestroyableSecretKey(secretKey.getEncoded(), secretKey.getAlgorithm());
		}
	}

	/**
	 * Creates a new key of given length and for use with given algorithm using entropy from the given csprng.
	 *
	 * @param csprng A cryptographically secure random number source
	 * @param algorithm The {@link #getAlgorithm() key algorithm}
	 * @param keyLenBytes The length of the key (in bytes)
	 * @return A new secret key
	 */
	public static DestroyableSecretKey generate(SecureRandom csprng, String algorithm, int keyLenBytes) {
		byte[] key = new byte[keyLenBytes];
		try {
			csprng.nextBytes(key);
			return new DestroyableSecretKey(key, algorithm);
		} finally {
			Arrays.fill(key, (byte) 0x00);
		}
	}

	@Override
	public String getAlgorithm() {
		Preconditions.checkState(!destroyed, "Key has been destroyed");
		return algorithm;
	}

	@Override
	public String getFormat() {
		Preconditions.checkState(!destroyed, "Key has been destroyed");
		return "RAW";
	}

	@Override
	public byte[] getEncoded() {
		Preconditions.checkState(!destroyed, "Key has been destroyed");
		return key.clone();
	}

	@Override
	public void destroy() {
		Arrays.fill(key, (byte) 0x00);
		destroyed = true;
	}

	@Override
	public boolean isDestroyed() {
		return destroyed;
	}

	/**
	 * Same as {@link #destroy()}
	 */
	@Override
	public void close() {
		destroy();
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		DestroyableSecretKey that = (DestroyableSecretKey) o;
		return algorithm.equals(that.algorithm) && MessageDigest.isEqual(this.key, that.key);
	}

	@Override
	public int hashCode() {
		int result = Objects.hash(algorithm);
		result = 31 * result + Arrays.hashCode(key);
		return result;
	}
}
