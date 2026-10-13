package org.cryptomator.cryptolib.internal;

import com.google.common.base.Preconditions;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.CiphertextReader;
import org.cryptomator.cryptolib.api.CiphertextWriter;
import org.cryptomator.cryptolib.api.VaultFile;
import org.cryptomator.cryptolib.common.ByteBuffers;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Format-independent {@link VaultFile}: range access and chunk arithmetic on top of a {@link FileLayout} and a {@link ChunkCodec}.
 * <p>
 * Instances are not thread-safe.
 */
public final class VaultFileImpl implements VaultFile {

	private final FileLayout layout;
	private final ChunkCodec codec;
	private final ByteBuffer encryptedHeader;
	private final byte[] headerNonce;
	private final DestroyableSecretKey fileKey;
	private final int seedId;
	private long size;
	private boolean headerPersisted;
	private ByteBuffer cleartextBuf; // working buffers, allocated on first use of the range operations
	private ByteBuffer ciphertextBuf;

	/**
	 * @param layout The format's layout
	 * @param codec The format's chunk codec
	 * @param header The file's header
	 * @param cleartextSize Current cleartext size
	 * @param headerPersisted Whether the header already exists in the ciphertext (false for newly created files)
	 */
	public VaultFileImpl(FileLayout layout, ChunkCodec codec, FileHeaderParts header, long cleartextSize, boolean headerPersisted) {
		this.layout = layout;
		this.codec = codec;
		this.encryptedHeader = header.encrypted().asReadOnlyBuffer();
		this.headerNonce = header.nonce();
		this.fileKey = header.fileKey();
		this.seedId = header.seedId();
		this.size = cleartextSize;
		this.headerPersisted = headerPersisted;
	}

	@Override
	public ByteBuffer encryptedHeader() {
		ByteBuffer result = encryptedHeader.duplicate();
		result.rewind();
		return result;
	}

	@Override
	public int seedId() {
		return seedId;
	}

	@Override
	public long size() {
		return size;
	}

	// HIGH LEVEL

	@Override
	public int read(long cleartextPosition, ByteBuffer dst, CiphertextReader ciphertextReader) throws IOException, AuthenticationFailedException {
		Preconditions.checkArgument(cleartextPosition >= 0, "position must not be negative");
		if (cleartextPosition >= size) {
			return -1;
		}
		long pos = cleartextPosition;
		int total = 0;
		while (dst.hasRemaining() && pos < size) {
			long chunkIndex = layout.chunkIndex(pos);
			ByteBuffer cleartextChunk = loadChunk(chunkIndex, ciphertextReader);
			cleartextChunk.position(layout.offsetInChunk(pos));
			int copied = ByteBuffers.copy(cleartextChunk, dst);
			pos += copied;
			total += copied;
		}
		return total;
	}

	@Override
	public int write(long cleartextPosition, ByteBuffer src, CiphertextReader ciphertextReader, CiphertextWriter ciphertextWriter) throws IOException, AuthenticationFailedException {
		Preconditions.checkArgument(cleartextPosition >= 0, "position must not be negative");
		int length = src.remaining();
		persistHeader(ciphertextWriter);
		if (cleartextPosition > size) {
			writeRegion(size, cleartextPosition - size, null, ciphertextReader, ciphertextWriter); // zero-fill the gap
		}
		writeRegion(cleartextPosition, length, src, ciphertextReader, ciphertextWriter);
		writeEofChunkIfNeeded(ciphertextWriter);
		return length;
	}

	@Override
	public void truncate(long newSize, CiphertextReader ciphertextReader, CiphertextWriter ciphertextWriter) throws IOException, AuthenticationFailedException {
		Preconditions.checkArgument(newSize >= 0 && newSize <= size, "new size %s must be within [0, %s]", newSize, size);
		if (newSize == size) {
			return;
		}
		int offset = layout.offsetInChunk(newSize);
		if (offset > 0) {
			long chunkIndex = layout.chunkIndex(newSize);
			ByteBuffer cleartextChunk = loadChunk(chunkIndex, ciphertextReader);
			cleartextChunk.limit(offset);
			storeChunk(chunkIndex, cleartextChunk, ciphertextWriter);
		}
		size = newSize;
		writeEofChunkIfNeeded(ciphertextWriter);
	}

	// writes [pos, pos + length) from src (or zeros if src is null); pos must not exceed the current size
	private void writeRegion(long pos, long length, ByteBuffer src, CiphertextReader in, CiphertextWriter out) throws IOException {
		assert pos <= size;
		long end = pos + length;
		long cur = pos;
		while (cur < end) {
			long chunkIndex = layout.chunkIndex(cur);
			int offset = layout.offsetInChunk(cur);
			int count = (int) Math.min(layout.cleartextChunkSize() - offset, end - cur);
			int existing = Math.max(0, layout.cleartextChunkLength(size, chunkIndex));
			ByteBuffer cleartextChunk;
			if (existing > 0 && !(offset == 0 && count >= existing)) {
				cleartextChunk = loadChunk(chunkIndex, in); // partial overwrite: read-modify-write
			} else {
				cleartextChunk = cleartextBuffer();
				cleartextChunk.clear().limit(0);
			}
			assert offset <= cleartextChunk.limit() : "writes are sequential, so no gap can open up inside a chunk";
			cleartextChunk.limit(Math.max(cleartextChunk.limit(), offset + count));
			cleartextChunk.position(offset);
			if (src != null) {
				ByteBuffer slice = src.duplicate();
				slice.limit(slice.position() + count);
				cleartextChunk.put(slice);
				src.position(src.position() + count);
			} else {
				Arrays.fill(cleartextChunk.array(), cleartextChunk.arrayOffset() + offset, cleartextChunk.arrayOffset() + offset + count, (byte) 0x00);
			}
			cleartextChunk.position(0);
			storeChunk(chunkIndex, cleartextChunk, out);
			cur += count;
			size = Math.max(size, cur);
		}
	}

	private void persistHeader(CiphertextWriter out) throws IOException {
		if (!headerPersisted) {
			writeFully(out, encryptedHeader(), 0);
			headerPersisted = true;
		}
	}

	private void writeEofChunkIfNeeded(CiphertextWriter out) throws IOException {
		if (layout.hasEofChunk() && size % layout.cleartextChunkSize() == 0) {
			ByteBuffer empty = cleartextBuffer();
			empty.clear().limit(0);
			storeChunk(layout.chunkCount(size) - 1, empty, out);
		}
	}

	// decrypts the chunk with the given index into the working buffer, which is returned flipped (position 0, limit = cleartext length)
	private ByteBuffer loadChunk(long chunkIndex, CiphertextReader in) throws IOException, AuthenticationFailedException {
		int ciphertextLength = layout.ciphertextChunkLength(size, chunkIndex);
		assert ciphertextLength > 0;
		ByteBuffer ciphertextChunk = ciphertextBuffer();
		ciphertextChunk.clear().limit(ciphertextLength);
		readFully(in, ciphertextChunk, layout.ciphertextChunkOffset(chunkIndex));
		ciphertextChunk.flip();
		ByteBuffer cleartextChunk = cleartextBuffer();
		cleartextChunk.clear();
		decryptChunk(ciphertextChunk, cleartextChunk, chunkIndex);
		cleartextChunk.flip();
		return cleartextChunk;
	}

	// encrypts the given cleartext (position to limit) as the chunk with the given index and writes it
	private void storeChunk(long chunkIndex, ByteBuffer cleartextChunk, CiphertextWriter out) throws IOException {
		ByteBuffer ciphertextChunk = ciphertextBuffer();
		ciphertextChunk.clear();
		encryptChunk(cleartextChunk, ciphertextChunk, chunkIndex);
		ciphertextChunk.flip();
		writeFully(out, ciphertextChunk, layout.ciphertextChunkOffset(chunkIndex));
	}

	private ByteBuffer cleartextBuffer() {
		if (cleartextBuf == null) {
			cleartextBuf = ByteBuffer.allocate(layout.cleartextChunkSize());
		}
		return cleartextBuf;
	}

	private ByteBuffer ciphertextBuffer() {
		if (ciphertextBuf == null) {
			ciphertextBuf = ByteBuffer.allocate(layout.ciphertextChunkSize());
		}
		return ciphertextBuf;
	}

	private static void readFully(CiphertextReader in, ByteBuffer buf, long position) throws IOException {
		long pos = position;
		while (buf.hasRemaining()) {
			int read = in.read(buf, pos);
			if (read <= 0) {
				throw new EOFException("Unexpected end of ciphertext at position " + pos);
			}
			pos += read;
		}
	}

	private static void writeFully(CiphertextWriter out, ByteBuffer buf, long position) throws IOException {
		long pos = position;
		while (buf.hasRemaining()) {
			int written = out.write(buf, pos);
			if (written <= 0) {
				throw new IOException("Ciphertext writer wrote " + written + " bytes");
			}
			pos += written;
		}
	}

	// CHUNK LAYER

	@Override
	public long chunkIndex(long cleartextPosition) {
		return layout.chunkIndex(cleartextPosition);
	}

	@Override
	public int offsetInChunk(long cleartextPosition) {
		return layout.offsetInChunk(cleartextPosition);
	}

	@Override
	public long ciphertextChunkOffset(long chunkIndex) {
		return layout.ciphertextChunkOffset(chunkIndex);
	}

	@Override
	public long cleartextChunkOffset(long chunkIndex) {
		return layout.cleartextChunkOffset(chunkIndex);
	}

	@Override
	public long chunkCount(long cleartextSize) {
		return layout.chunkCount(cleartextSize);
	}

	@Override
	public void encryptChunk(ByteBuffer cleartextChunk, ByteBuffer ciphertextChunk, long chunkIndex) {
		assertNotDestroyed();
		codec.encryptChunk(headerNonce, fileKey, cleartextChunk, ciphertextChunk, chunkIndex);
	}

	@Override
	public void decryptChunk(ByteBuffer ciphertextChunk, ByteBuffer cleartextChunk, long chunkIndex) throws AuthenticationFailedException {
		assertNotDestroyed();
		codec.decryptChunk(headerNonce, fileKey, ciphertextChunk, cleartextChunk, chunkIndex);
	}

	// LIFECYCLE

	@Override
	public boolean isDestroyed() {
		return fileKey.isDestroyed();
	}

	@Override
	public void destroy() {
		fileKey.destroy();
		if (cleartextBuf != null) {
			Arrays.fill(cleartextBuf.array(), (byte) 0x00);
		}
	}

	private void assertNotDestroyed() {
		if (isDestroyed()) {
			throw new IllegalStateException("File key destroyed");
		}
	}

}
