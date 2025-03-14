package org.cryptomator.cryptolib.common;

import com.google.common.base.Preconditions;

import javax.crypto.SecretKey;
import javax.security.auth.Destroyable;
import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/**
 * A {@link SecretKey} that (<a href="https://bugs.openjdk.java.net/browse/JDK-8160206">other than JDK's SecretKeySpec</a>)
 * actually implements {@link Destroyable}.
 * <p>
 * Furthermore, this implementation will not create copies when accessing {@link #getEncoded()}.
 * Instead, it implements {@link #copy} and {@link AutoCloseable} in an exception-free manner. To prevent mutation of the exposed key,
 * you would want to make sure to always work on scoped copies, such as in this example:
 *
 * <pre>
 *     // copy "key" to protect it from unwanted modifications:
 *     try (DestroyableSecretKey k = key.copy()) {
 *         // use "k":
 *         Cipher cipher = Cipher.init(k, ...)
 *         cipher.doFinal(...)
 *     } // "k" will get destroyed here
 * </pre>
 */
public class DestroyableSecretKey implements SecretKey, AutoCloseable {

	private static final String KEY_DESTROYED_ERROR = "Key has been destroyed";

	private final transient byte[] key;
	private final String algorithm;
	private boolean destroyed;

	/**
	 * Convenience constructor for {@link #DestroyableSecretKey(byte[], int, int, String)}
	 *
	 * @param key       The raw key data (will get copied)
	 * @param algorithm The {@link #getAlgorithm() algorithm name}
	 */
	public DestroyableSecretKey(byte[] key, String algorithm) {
		this(key, 0, key.length, algorithm);
	}

	/**
	 * Creates a new destroyable secret key, copying of the provided raw key bytes.
	 *
	 * @param key       A byte[] holding the key material (relevant part will get copied)
	 * @param offset    The offset within <code>key</code> where the key starts
	 * @param len       The number of bytes beginning at <code>offset</code> to read from <code>key</code>
	 * @param algorithm The {@link #getAlgorithm() algorithm name}
	 */
	public DestroyableSecretKey(byte[] key, int offset, int len, String algorithm) {
		Preconditions.checkArgument(offset >= 0, "Invalid offset");
		Preconditions.checkArgument(len >= 0, "Invalid length");
		Preconditions.checkArgument(key.length >= offset + len, "Invalid offset/len");
		this.key = new byte[len];
		this.algorithm = Preconditions.checkNotNull(algorithm, "Algorithm must not be null");
		this.destroyed = false;
		System.arraycopy(key, offset, this.key, 0, len);
	}

	/**
	 * Casts or converts a given {@link SecretKey} to a DestroyableSecretKey
	 *
	 * @param secretKey The secret key
	 * @return Either the provided or a new key, depending on whether the provided key is already a DestroyableSecretKey
	 */
	public static DestroyableSecretKey from(Key secretKey) {
		if (secretKey instanceof DestroyableSecretKey) {
			return (DestroyableSecretKey) secretKey;
		} else {
			return new DestroyableSecretKey(secretKey.getEncoded(), secretKey.getAlgorithm());
		}
	}

	/**
	 * Creates a new key of given length and for use with given algorithm using entropy from the given csprng.
	 *
	 * @param csprng      A cryptographically secure random number source
	 * @param algorithm   The {@link #getAlgorithm() key algorithm}
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
		Preconditions.checkState(!destroyed, KEY_DESTROYED_ERROR);
		return algorithm;
	}

	@Override
	public String getFormat() {
		Preconditions.checkState(!destroyed, KEY_DESTROYED_ERROR);
		return "RAW";
	}

	/**
	 * Returns the raw key bytes this instance wraps.
	 * <p>
	 * <b>Important:</b> Any change to the returned array will reflect in this key. Make sure to
	 * {@link #copy() make a local copy} if you can't rule out mutations.
	 *
	 * @return A byte array holding the secret key
	 */
	@Override
	public byte[] getEncoded() {
		Preconditions.checkState(!destroyed, KEY_DESTROYED_ERROR);
		return key;
	}

	/**
	 * Returns an independent copy of this key
	 * @return New copy of <code>this</code>
	 */
	public DestroyableSecretKey copy() {
		Preconditions.checkState(!destroyed, KEY_DESTROYED_ERROR);
		return new DestroyableSecretKey(key, algorithm); // key will get copied by the constructor as per contract
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
