package org.cryptomator.cryptolib.examples;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.NameShortener;
import org.cryptomator.cryptolib.api.ShortenedVaultNode;
import org.cryptomator.cryptolib.api.UvfKeyEncryptionKey;
import org.cryptomator.cryptolib.api.UvfRecoveryKey;
import org.cryptomator.cryptolib.api.UvfUnlockedVault;
import org.cryptomator.cryptolib.api.VaultDirectory;
import org.cryptomator.cryptolib.api.VaultNode;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * Example of a Unified Vault Format vault in a local directory, with name shortening as a storage layer of its own: {@link ShorteningStorage} keeps stored names short without any
 * key, and the code above it deals with name encryption only and never sees a shortened name or a sidecar.
 * <p>
 * The layering is optional. Handling encryption and shortening in one place, as {@link Cvf8Example} does, works for UVF as well: apart from creating the vault, that example does not
 * depend on the format and yields the same files.
 */
public final class UvfExample {

	private final UvfUnlockedVault vault;
	private final ShorteningStorage storage;

	/**
	 * @param vaultDir The vault's root directory
	 * @param vault The unlocked vault stored in {@code vaultDir}
	 */
	public UvfExample(Path vaultDir, UvfUnlockedVault vault) {
		this.vault = vault;
		this.storage = new ShorteningStorage(vaultDir, NameShortener.uvf(vault.nameShorteningThreshold())); // the threshold is all the lower layer needs
	}

	/**
	 * Creates a vault: {@code vault.uvf} and the root directory.
	 *
	 * @param vaultDir An empty directory
	 * @param password Protects the vault
	 * @param csprng Source of randomness
	 * @return The unlocked vault, whose {@code serializedRecoveryKey()} is to be shown to the user
	 * @throws IOException If writing fails
	 */
	public static UvfUnlockedVault createVault(Path vaultDir, CharSequence password, SecureRandom csprng) throws IOException {
		UvfUnlockedVault vault = UvfUnlockedVault.create(csprng, UvfKeyEncryptionKey.password(password), UvfRecoveryKey.generate(csprng), 220); // ciphertext names with more than 220 bytes get shortened
		UvfExample example = new UvfExample(vaultDir, vault);
		example.storage.write(vault.configFileName(), vault.serializeConfig());
		vault.rootDirectory().writeMetadataBackup(example.storage::write); // d/XX/YYY…/dir.uvf
		return vault;
	}

	/**
	 * @param parent The directory to create the file in
	 * @param cleartextName The file's name
	 * @param cleartext The file's contents
	 * @throws IOException If writing fails
	 */
	public void writeFile(VaultDirectory parent, String cleartextName, byte[] cleartext) throws IOException {
		VaultNode node = parent.encryptName(cleartextName);
		storage.write(parent.dirPath() + "/" + node.name(), vault.encryptFile(cleartext));
	}

	/**
	 * @param parent The directory containing the file
	 * @param cleartextName The file's name
	 * @return The file's contents
	 * @throws IOException If reading fails, e.g. because there is no such file
	 */
	public byte[] readFile(VaultDirectory parent, String cleartextName) throws IOException {
		VaultNode node = parent.encryptName(cleartextName);
		return vault.decryptFile(storage.read(parent.dirPath() + "/" + node.name()));
	}

	/**
	 * @param parent The directory to create the subdirectory in
	 * @param cleartextName The subdirectory's name
	 * @return The new directory
	 * @throws IOException If writing fails
	 */
	public VaultDirectory createDirectory(VaultDirectory parent, String cleartextName) throws IOException {
		VaultDirectory child = vault.newDirectory();
		parent.createDirectory(parent.encryptName(cleartextName), child, storage::write); // <name>/dir.uvf and the child's d/XX/YYY…/dir.uvf
		return child;
	}

	/**
	 * @param parent The directory containing the subdirectory
	 * @param cleartextName The subdirectory's name
	 * @return The subdirectory
	 * @throws IOException If reading fails, e.g. because there is no such directory
	 */
	public VaultDirectory directory(VaultDirectory parent, String cleartextName) throws IOException {
		return parent.directory(parent.encryptName(cleartextName), storage::read);
	}

	/**
	 * @param dir The directory to list
	 * @return The cleartext names of the directory's children
	 * @throws IOException If reading fails
	 */
	public List<String> list(VaultDirectory dir) throws IOException {
		List<String> cleartextNames = new ArrayList<>();
		for (String ciphertextName : storage.list(dir.dirPath())) {
			try {
				cleartextNames.add(dir.decryptName(ciphertextName));
			} catch (AuthenticationFailedException | IllegalArgumentException e) {
				// skip: not a node (dir.uvf) or an unauthentic name
			}
		}
		return cleartextNames;
	}

	/**
	 * The lower layer: stores files below a local directory under paths whose components may be arbitrarily long. It knows nothing about keys or name encryption.
	 */
	public static final class ShorteningStorage {

		private final Path root;
		private final NameShortener shortener;

		/**
		 * @param root The directory to store files in
		 * @param shortener Decides which names are too long and how they are stored
		 */
		public ShorteningStorage(Path root, NameShortener shortener) {
			this.root = root;
			this.shortener = shortener;
		}

		/**
		 * @param path Path of a file relative to the root, with full names and {@code /} as separator
		 * @return The file's contents
		 * @throws IOException If reading fails
		 */
		public byte[] read(String path) throws IOException {
			return Files.readAllBytes(resolve(path, false));
		}

		/**
		 * @param path Path of a file relative to the root, with full names and {@code /} as separator; missing parent directories are created
		 * @param contents The file's contents
		 * @throws IOException If writing fails
		 */
		public void write(String path, byte[] contents) throws IOException {
			Path file = resolve(path, true);
			Files.createDirectories(file.getParent());
			Files.write(file, contents);
		}

		/**
		 * @param path Path of a directory relative to the root, with full names and {@code /} as separator
		 * @return The full names of the directory's entries
		 * @throws IOException If reading fails
		 */
		public List<String> list(String path) throws IOException {
			Path dir = resolve(path, false);
			List<String> names = new ArrayList<>();
			try (DirectoryStream<Path> entries = Files.newDirectoryStream(dir)) {
				for (Path entry : entries) {
					String entryName = entry.getFileName().toString();
					if (shortener.isSidecar(entryName)) {
						continue; // <hash>.original.uvf: represented by its <hash>.shortened.uvf sibling
					} else if (!shortener.isShortened(entryName)) {
						names.add(entryName);
						continue;
					}
					try {
						byte[] sidecar = Files.readAllBytes(dir.resolve(shortener.sidecarFile(entryName)));
						names.add(shortener.unshorten(entryName, sidecar)); // verifies that the sidecar belongs to this entry
					} catch (NoSuchFileException | AuthenticationFailedException e) {
						// skip: sidecar missing or not matching
					}
				}
			}
			return names;
		}

		// maps a path of full names to the stored path; on the way to a file being written, long names get their sidecar
		private Path resolve(String path, boolean writeSidecars) throws IOException {
			Path result = root;
			for (String name : path.split("/")) {
				ShortenedVaultNode shortened = shortener.shorten(name); // null unless the name exceeds the threshold
				if (shortened == null) {
					result = result.resolve(name);
					continue;
				}
				if (writeSidecars) {
					Files.createDirectories(result);
					Files.write(result.resolve(shortened.sidecarFile()), shortened.sidecarContents()); // <hash>.original.uvf
				}
				result = result.resolve(shortened.shortenedName()); // <hash>.shortened.uvf
			}
			return result;
		}

	}

}
