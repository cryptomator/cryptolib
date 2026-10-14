package org.cryptomator.cryptolib.api;

import javax.security.auth.Destroyable;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;

/**
 * An unlocked vault: the entry point for everything that is encrypted or decrypted within it.
 * <p>
 * Every instance is either a {@link Cvf8UnlockedVault} or a {@link UvfUnlockedVault}. Format-agnostic code only needs this interface. An unlocked vault holds key material and must be
 * {@link #destroy() destroyed} (or closed) when no longer needed.
 *
 * @implNote Java 25+ variant of the interface, sealed so that consumers can switch over it exhaustively. Keep in sync with {@code src/main/java/.../UnlockedVault.java}.
 */
public sealed interface UnlockedVault extends Destroyable, AutoCloseable permits Cvf8UnlockedVault, UvfUnlockedVault {

	// CONFIG

	/**
	 * @return The file name under which this format stores its configuration in the vault root ({@code vault.cryptomator} or {@code vault.uvf})
	 */
	String configFileName();

	/**
	 * Serializes the current configuration, e.g. to write it to {@link #configFileName()} after creating the vault or changing it.
	 *
	 * @return The contents of the configuration file
	 */
	byte[] serializeConfig();

	/**
	 * Encodes the vault's recovery key as a sequence of words for the user to write down: the masterkey of a CVF8 vault, the private recovery key of a UVF vault.
	 * <p>
	 * {@link LockedVault#recover(CharSequence, java.security.SecureRandom)} accepts the result. The encoding (key bytes, a CRC32-based checksum and, for UVF, padding, mapped onto a 4096-word
	 * dictionary) is shared with Cryptomator and Cryptomator Hub.
	 *
	 * @return The recovery key as space-separated words
	 * @throws IllegalStateException If this UVF vault only knows the public part of its recovery key, i.e. it was neither created with {@link UvfUnlockedVault#setRecoveryKey(java.security.KeyPair)}
	 * nor unlocked with the recovery key
	 */
	String serializedRecoveryKey();

	// DIRECTORIES

	/**
	 * @return The vault's root directory
	 */
	VaultDirectory rootDirectory();

	/**
	 * Creates the metadata for a new, not yet existing directory.
	 *
	 * @return A directory with a fresh random id
	 */
	VaultDirectory newDirectory();

	/**
	 * Resolves a directory from the contents of its {@code dir.c9r} / {@code dir.uvf} file.
	 *
	 * @param dirFileContents The contents of the directory file found inside the parent's node directory
	 * @return The directory
	 * @throws AuthenticationFailedException If the contents are unauthentic
	 * @throws IllegalArgumentException If the contents are malformed
	 */
	VaultDirectory directory(byte[] dirFileContents) throws AuthenticationFailedException;

	/**
	 * Resolves a directory from the contents of the backup copy of its metadata stored inside the directory itself ({@code dirid.c9r} / {@code dir.uvf}).
	 *
	 * @param backupFileContents The contents of the file at {@link VaultDirectory#backupFilePath()}
	 * @return The directory
	 * @throws AuthenticationFailedException If the contents are unauthentic
	 * @throws IllegalArgumentException If the contents are malformed
	 */
	VaultDirectory directoryFromBackup(byte[] backupFileContents) throws AuthenticationFailedException;

	/**
	 * Computes the longest cleartext name that can be stored when the underlying file system limits ciphertext names to the given length.
	 *
	 * @param maxCiphertextNameLength Maximum length of a file name supported by the file system storing the vault
	 * @return Maximum number of UTF-8 bytes of a cleartext name
	 */
	int maxCleartextNameLength(int maxCiphertextNameLength);

	// FILES

	/**
	 * Creates a new file with a fresh header. The header is written to the ciphertext on the first write.
	 *
	 * @return An empty file
	 */
	VaultFile createFile();

	/**
	 * Opens an existing file from its encrypted header.
	 *
	 * @param encryptedHeader The first {@link #headerSize()} bytes of the ciphertext file, from the buffer's position to its limit
	 * @param ciphertextFileSize The total size of the ciphertext file in bytes, including the header
	 * @return The file, with {@link VaultFile#size()} derived from {@code ciphertextFileSize}
	 * @throws AuthenticationFailedException If the header is unauthentic
	 * @throws IllegalArgumentException If the header is malformed, refers to an unknown key revision, or {@code ciphertextFileSize} is impossible for this format
	 */
	VaultFile openFile(ByteBuffer encryptedHeader, long ciphertextFileSize) throws AuthenticationFailedException;

	/**
	 * Encrypts a complete file held in memory.
	 *
	 * @param cleartext The file's cleartext contents
	 * @return The complete ciphertext file, including the header
	 */
	byte[] encryptFile(byte[] cleartext);

	/**
	 * Decrypts a complete file held in memory.
	 *
	 * @param ciphertext The complete ciphertext file, including the header
	 * @return The file's cleartext contents
	 * @throws AuthenticationFailedException If the header or any chunk is unauthentic
	 * @throws IllegalArgumentException If the ciphertext is structurally invalid (e.g. truncated)
	 */
	byte[] decryptFile(byte[] ciphertext) throws AuthenticationFailedException;

	/**
	 * Wraps a channel so that all bytes written to the returned channel are encrypted and written to {@code ciphertextSink}, header first.
	 *
	 * @param ciphertextSink Where the ciphertext goes
	 * @return A channel accepting cleartext; closing it flushes the final chunk and closes {@code ciphertextSink}
	 */
	WritableByteChannel encryptingChannel(WritableByteChannel ciphertextSink);

	/**
	 * Wraps a channel so that reading from the returned channel yields the decrypted contents of {@code ciphertextSource}.
	 *
	 * @param ciphertextSource Where the ciphertext (including the header) comes from
	 * @return A channel yielding cleartext; every chunk is authenticated, an unauthentic chunk results in an {@link AuthenticationFailedException} from {@code read}
	 */
	ReadableByteChannel decryptingChannel(ReadableByteChannel ciphertextSource);

	/**
	 * Wraps a channel so that reading from the returned channel yields the encrypted form of {@code cleartextSource}, header first.
	 *
	 * @param cleartextSource Where the cleartext comes from
	 * @return A channel yielding ciphertext
	 */
	ReadableByteChannel encryptingChannel(ReadableByteChannel cleartextSource);

	/**
	 * Stream adapter for {@link #encryptingChannel(WritableByteChannel)}.
	 *
	 * @param ciphertextSink Where the ciphertext goes
	 * @return A stream accepting cleartext; closing it flushes the final chunk and closes {@code ciphertextSink}
	 */
	OutputStream encryptingStream(OutputStream ciphertextSink);

	/**
	 * Stream adapter for {@link #decryptingChannel(ReadableByteChannel)}.
	 *
	 * @param ciphertextSource Where the ciphertext (including the header) comes from
	 * @return A stream yielding cleartext
	 */
	InputStream decryptingStream(InputStream ciphertextSource);

	// FILE LAYOUT

	/**
	 * @return Size of an encrypted file header in bytes
	 */
	int headerSize();

	/**
	 * @return Number of cleartext bytes per chunk
	 */
	int cleartextChunkSize();

	/**
	 * @return Number of ciphertext bytes per chunk
	 */
	int ciphertextChunkSize();

	/**
	 * Computes the size of the ciphertext file for a file of the given cleartext size.
	 *
	 * @param cleartextSize Size of the cleartext in bytes
	 * @return Size of the ciphertext file in bytes, including the header
	 */
	long ciphertextSize(long cleartextSize);

	/**
	 * Computes the cleartext size of a file from the size of its ciphertext file.
	 *
	 * @param ciphertextFileSize Size of the ciphertext file in bytes, including the header
	 * @return Size of the cleartext in bytes
	 * @throws IllegalArgumentException If no valid file of this format can have the given size
	 */
	long cleartextSize(long ciphertextFileSize);

	// SYMLINKS

	/**
	 * Encrypts a symbolic link's target for storage in the link's {@code symlink.c9r} / {@code symlink.uvf} file.
	 *
	 * @param target The link target as it would be passed to {@code Files.createSymbolicLink}
	 * @return The contents of the symlink file
	 */
	byte[] encryptSymlinkTarget(String target);

	/**
	 * Decrypts a symbolic link's target.
	 *
	 * @param symlinkFileContents The contents of the link's {@code symlink.c9r} / {@code symlink.uvf} file
	 * @return The link target
	 * @throws AuthenticationFailedException If the contents are unauthentic
	 */
	String decryptSymlinkTarget(byte[] symlinkFileContents) throws AuthenticationFailedException;

	// LIFECYCLE

	/**
	 * Destroys all key material held by this vault.
	 */
	@Override
	void destroy();

	/**
	 * Same as {@link #destroy()}.
	 */
	@Override
	default void close() {
		destroy();
	}

}
