package org.cryptomator.cryptolib.ecies;

import org.cryptomator.cryptolib.common.MessageDigestSupplier;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.DigestException;
import java.util.Arrays;

@FunctionalInterface
public interface KeyDerivationFunction {

	KeyDerivationFunction ANSI_X963_SHA256_KDF = (sharedSecret, keyDataLen) -> ansiX963sha256Kdf(sharedSecret, new byte[0], keyDataLen);

	/**
	 * Derives a key of desired length
	 *
	 * @param sharedSecret A shared secret
	 * @param keyDataLen   Desired key length (in bytes)
	 * @return key data
	 */
	byte[] deriveKey(byte[] sharedSecret, int keyDataLen);

	/**
	 * Performs <a href="https://www.secg.org/sec1-v2.pdf">ANSI-X9.63-KDF</a> with SHA-256
	 *
	 * @param sharedSecret A shared secret
	 * @param sharedInfo   Additional authenticated data
	 * @param keyDataLen   Desired key length (in bytes)
	 * @return key data
	 */
	static byte[] ansiX963sha256Kdf(byte[] sharedSecret, byte[] sharedInfo, int keyDataLen) {
		// max input length is 2^64 - 1, see https://doi.org/10.6028/NIST.SP.800-56Cr2, Table 1
		int hashLen = 32; // fixed digest length for SHA-256 in bytes

		// These two checks must be performed according to spec. However with 32 bit integers, we can't exceed any limits anyway:
		assert BigInteger.valueOf(4L + sharedSecret.length + sharedInfo.length).compareTo(BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE)) < 0 : "input larger than hashmaxlen";
		assert keyDataLen < (1L << 32 - 1) * hashLen : "keyDataLen larger than hashLen × (2^32 − 1)";

		ByteBuffer counter = ByteBuffer.allocate(Integer.BYTES);
		assert ByteOrder.BIG_ENDIAN.equals(counter.order());
		int n = (keyDataLen + hashLen - 1) / hashLen;
		byte[] buffer = new byte[n * hashLen];
		try (MessageDigestSupplier.ReusableMessageDigest sha256 = MessageDigestSupplier.SHA256.instance()) {
			for (int i = 0; i < n; i++) {
				sha256.get().update(sharedSecret);
				counter.clear();
				counter.putInt(i + 1);
				counter.flip();
				sha256.get().update(counter);
				sha256.get().update(sharedInfo);
				sha256.get().digest(buffer, i * hashLen, hashLen);
			}
			return Arrays.copyOf(buffer, keyDataLen);
		} catch (DigestException e) {
			throw new IllegalStateException("Invalid digest output buffer offset", e);
		} finally {
			Arrays.fill(buffer, (byte) 0x00);
		}
	}

}
