package org.cryptomator.cryptolib.common;
/*******************************************************************************
 * Copyright (c) 2015, 2016 Sebastian Stenzel and others.
 * This file is licensed under the terms of the MIT license.
 * See the LICENSE.txt file for more info.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/

import javax.crypto.Mac;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.util.Arrays;

import static java.nio.charset.StandardCharsets.UTF_8;

public class Scrypt {

	private static final int P = 1; // scrypt parallelization parameter

	private Scrypt() {
	}

	/**
	 * Derives a key from the given passphrase.
	 * This implementation makes sure, any copies of the passphrase used during key derivation are overwritten in memory asap (before next GC cycle).
	 *
	 * @param passphrase       The passphrase, whose characters will get UTF-8 encoded during key derivation.
	 * @param salt             Salt, ideally randomly generated
	 * @param costParam        Cost parameter <code>N</code>, larger than 1, a power of 2 and less than <code>2^(128 * blockSize / 8)</code>
	 * @param blockSize        Block size <code>r</code>
	 * @param keyLengthInBytes Key output length <code>dkLen</code>
	 * @return Derived key
	 * @see <a href="https://tools.ietf.org/html/rfc7914#section-2">RFC 7914</a>
	 */
	public static byte[] scrypt(CharSequence passphrase, byte[] salt, int costParam, int blockSize, int keyLengthInBytes) {
		// This is an attempt to get the password bytes without copies of the password being created in some dark places inside the JVM:
		final ByteBuffer buf = UTF_8.encode(CharBuffer.wrap(passphrase));
		final byte[] pw = new byte[buf.remaining()];
		buf.get(pw);
		try {
			return scrypt(pw, salt, costParam, blockSize, keyLengthInBytes);
		} finally {
			Arrays.fill(pw, (byte) 0); // overwrite bytes
			buf.rewind(); // just resets markers
			buf.put(pw); // this is where we overwrite the actual bytes
		}
	}

	/**
	 * Derives a key from the given passphrase.
	 * This implementation makes sure, any copies of the passphrase used during key derivation are overwritten in memory asap (before next GC cycle).
	 *
	 * @param passphrase       The passphrase,
	 * @param salt             Salt, ideally randomly generated
	 * @param costParam        Cost parameter <code>N</code>, larger than 1, a power of 2 and less than <code>2^(128 * blockSize / 8)</code>
	 * @param blockSize        Block size <code>r</code>
	 * @param keyLengthInBytes Key output length <code>dkLen</code>
	 * @return Derived key
	 * @author Derived from com.lambdaworks.crypto.SCrypt, Apache License 2.0, Copyright (C) 2011 - Will Glozer
	 * @see <a href="https://tools.ietf.org/html/rfc7914#section-2">RFC 7914</a>
	 */
	public static byte[] scrypt(byte[] passphrase, byte[] salt, int costParam, int blockSize, int keyLengthInBytes) {
		if (costParam < 2 || (costParam & (costParam - 1)) != 0) {
			throw new IllegalArgumentException("N must be a power of 2 greater than 1");
		}
		if (costParam > Integer.MAX_VALUE / 128 / blockSize) {
			throw new IllegalArgumentException("Parameter N is too large");
		}
		if (blockSize > Integer.MAX_VALUE / 128 / P) {
			throw new IllegalArgumentException("Parameter r is too large");
		}

		try (DestroyableSecretKey key = new DestroyableSecretKey(passphrase, "HmacSHA256");
			 ObjectPool.Lease<Mac> mac = MacSupplier.HMAC_SHA256.keyed(key)) {

			byte[] DK = new byte[keyLengthInBytes];
			byte[] B = new byte[128 * blockSize * P];
			byte[] XY = new byte[256 * blockSize];
			byte[] V = new byte[128 * blockSize * costParam];

			pbkdf2(mac.get(), salt, 1, B, P * 128 * blockSize);

			for (int i = 0; i < P; i++) {
				smix(B, i * 128 * blockSize, blockSize, costParam, V, XY);
			}

			pbkdf2(mac.get(), B, 1, DK, keyLengthInBytes);

			return DK;
		}
	}

	/**
	 * Implementation of PBKDF2 (RFC2898).
	 *
	 * @param mac   Pre-initialized {@link Mac} instance to use.
	 * @param S     Salt.
	 * @param c     Iteration count.
	 * @param DK    Byte array that derived key will be placed in.
	 * @param dkLen Intended length, in octets, of the derived key.
	 * @author Derived from com.lambdaworks.crypto.PBKDF, Apache License 2.0, Copyright (C) 2011 - Will Glozer
	 */
	private static void pbkdf2(Mac mac, byte[] S, int c, byte[] DK, int dkLen) {
		int hLen = mac.getMacLength();

		if (dkLen > (Math.pow(2, 32) - 1) * hLen) {
			throw new IllegalArgumentException("Requested key length too long");
		}

		byte[] U;
		byte[] T = new byte[hLen];
		byte[] block1 = new byte[S.length + 4];

		int l = (int) Math.ceil((double) dkLen / hLen);
		int r = dkLen - (l - 1) * hLen;

		System.arraycopy(S, 0, block1, 0, S.length);

		for (int i = 1; i <= l; i++) {
			block1[S.length + 0] = (byte) (i >> 24 & 0xff);
			block1[S.length + 1] = (byte) (i >> 16 & 0xff);
			block1[S.length + 2] = (byte) (i >> 8 & 0xff);
			block1[S.length + 3] = (byte) (i >> 0 & 0xff);

			U = mac.doFinal(block1);
			System.arraycopy(U, 0, T, 0, hLen);

			for (int j = 1; j < c; j++) {
				U = mac.doFinal(U);

				for (int k = 0; k < hLen; k++) {
					T[k] ^= U[k];
				}
			}

			System.arraycopy(T, 0, DK, (i - 1) * hLen, (i == l ? r : hLen));
		}
	}

	private static void smix(byte[] B, int Bi, int r, int N, byte[] V, byte[] XY) {
		int Xi = 0;
		int Yi = 128 * r;
		int i;

		System.arraycopy(B, Bi, XY, Xi, 128 * r);

		for (i = 0; i < N; i++) {
			System.arraycopy(XY, Xi, V, i * (128 * r), 128 * r);
			blockmixSalsa8(XY, Xi, Yi, r);
		}

		for (i = 0; i < N; i++) {
			int j = integerify(XY, Xi, r) & (N - 1);
			blockxor(V, j * (128 * r), XY, Xi, 128 * r);
			blockmixSalsa8(XY, Xi, Yi, r);
		}

		System.arraycopy(XY, Xi, B, Bi, 128 * r);
	}

	private static void blockmixSalsa8(byte[] BY, int Bi, int Yi, int r) {
		byte[] X = new byte[64];
		int i;

		System.arraycopy(BY, Bi + (2 * r - 1) * 64, X, 0, 64);

		for (i = 0; i < 2 * r; i++) {
			blockxor(BY, i * 64, X, 0, 64);
			salsa20_8(X);
			System.arraycopy(X, 0, BY, Yi + (i * 64), 64);
		}

		for (i = 0; i < r; i++) {
			System.arraycopy(BY, Yi + (i * 2) * 64, BY, Bi + (i * 64), 64);
		}

		for (i = 0; i < r; i++) {
			System.arraycopy(BY, Yi + (i * 2 + 1) * 64, BY, Bi + (i + r) * 64, 64);
		}
	}

	private static int r(int a, int b) {
		return (a << b) | (a >>> (32 - b));
	}

	private static void salsa20_8(byte[] B) {
		int[] B32 = new int[16];
		int[] x = new int[16];
		int i;

		for (i = 0; i < 16; i++) {
			B32[i] = (B[i * 4 + 0] & 0xff) << 0;
			B32[i] |= (B[i * 4 + 1] & 0xff) << 8;
			B32[i] |= (B[i * 4 + 2] & 0xff) << 16;
			B32[i] |= (B[i * 4 + 3] & 0xff) << 24;
		}

		System.arraycopy(B32, 0, x, 0, 16);

		for (i = 8; i > 0; i -= 2) {
			x[4] ^= r(x[0] + x[12], 7);
			x[8] ^= r(x[4] + x[0], 9);
			x[12] ^= r(x[8] + x[4], 13);
			x[0] ^= r(x[12] + x[8], 18);
			x[9] ^= r(x[5] + x[1], 7);
			x[13] ^= r(x[9] + x[5], 9);
			x[1] ^= r(x[13] + x[9], 13);
			x[5] ^= r(x[1] + x[13], 18);
			x[14] ^= r(x[10] + x[6], 7);
			x[2] ^= r(x[14] + x[10], 9);
			x[6] ^= r(x[2] + x[14], 13);
			x[10] ^= r(x[6] + x[2], 18);
			x[3] ^= r(x[15] + x[11], 7);
			x[7] ^= r(x[3] + x[15], 9);
			x[11] ^= r(x[7] + x[3], 13);
			x[15] ^= r(x[11] + x[7], 18);
			x[1] ^= r(x[0] + x[3], 7);
			x[2] ^= r(x[1] + x[0], 9);
			x[3] ^= r(x[2] + x[1], 13);
			x[0] ^= r(x[3] + x[2], 18);
			x[6] ^= r(x[5] + x[4], 7);
			x[7] ^= r(x[6] + x[5], 9);
			x[4] ^= r(x[7] + x[6], 13);
			x[5] ^= r(x[4] + x[7], 18);
			x[11] ^= r(x[10] + x[9], 7);
			x[8] ^= r(x[11] + x[10], 9);
			x[9] ^= r(x[8] + x[11], 13);
			x[10] ^= r(x[9] + x[8], 18);
			x[12] ^= r(x[15] + x[14], 7);
			x[13] ^= r(x[12] + x[15], 9);
			x[14] ^= r(x[13] + x[12], 13);
			x[15] ^= r(x[14] + x[13], 18);
		}

		for (i = 0; i < 16; ++i)
			B32[i] = x[i] + B32[i];

		for (i = 0; i < 16; i++) {
			B[i * 4 + 0] = (byte) (B32[i] >> 0 & 0xff);
			B[i * 4 + 1] = (byte) (B32[i] >> 8 & 0xff);
			B[i * 4 + 2] = (byte) (B32[i] >> 16 & 0xff);
			B[i * 4 + 3] = (byte) (B32[i] >> 24 & 0xff);
		}
	}

	private static void blockxor(byte[] S, int Si, byte[] D, int Di, int len) {
		for (int i = 0; i < len; i++) {
			D[Di + i] ^= S[Si + i];
		}
	}

	private static int integerify(byte[] B, int Bi, int r) {
		int n;

		Bi += (2 * r - 1) * 64;

		n = (B[Bi + 0] & 0xff) << 0;
		n |= (B[Bi + 1] & 0xff) << 8;
		n |= (B[Bi + 2] & 0xff) << 16;
		n |= (B[Bi + 3] & 0xff) << 24;

		return n;
	}

}
