package org.cryptomator.cryptolib.common;

import org.cryptomator.cryptolib.api.CiphertextReader;
import org.cryptomator.cryptolib.api.CiphertextWriter;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * A growable in-memory ciphertext file for testing positional access via {@link CiphertextReader} / {@link CiphertextWriter}.
 */
public class InMemoryCiphertext implements CiphertextReader, CiphertextWriter {

	private byte[] data = new byte[0];

	public InMemoryCiphertext() {
	}

	public InMemoryCiphertext(byte[] initialContents) {
		this.data = initialContents.clone();
	}

	@Override
	public int read(ByteBuffer dst, long ciphertextPosition) {
		if (ciphertextPosition >= data.length) {
			return -1;
		}
		int n = (int) Math.min(dst.remaining(), data.length - ciphertextPosition);
		dst.put(data, (int) ciphertextPosition, n);
		return n;
	}

	@Override
	public int write(ByteBuffer src, long ciphertextPosition) {
		int n = src.remaining();
		long end = ciphertextPosition + n;
		if (end > data.length) {
			data = Arrays.copyOf(data, (int) end);
		}
		src.get(data, (int) ciphertextPosition, n);
		return n;
	}

	public void truncate(long length) {
		data = Arrays.copyOf(data, (int) length);
	}

	public long size() {
		return data.length;
	}

	public byte[] toByteArray() {
		return data.clone();
	}

	public void flipBit(int position) {
		data[position] ^= 0x01;
	}

}
