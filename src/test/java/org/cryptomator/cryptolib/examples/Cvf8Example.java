package org.cryptomator.cryptolib.examples;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.Cvf8UnlockedVault;
import org.cryptomator.cryptolib.api.CvfMasterkey;
import org.cryptomator.cryptolib.api.NameShortener;
import org.cryptomator.cryptolib.api.ShortenedVaultNode;
import org.cryptomator.cryptolib.api.UnlockedVault;
import org.cryptomator.cryptolib.api.VaultDirectory;
import org.cryptomator.cryptolib.api.VaultNode;
import org.cryptomator.cryptolib.common.MasterkeyFileAccess;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * Example of a Cryptomator Vault Format 8 vault in a local directory, with name encryption and name shortening handled in one place: every operation encrypts or decrypts a name and
 * applies the {@link NameShortener} right away.
 * <p>
 * Only {@link #createVault(Path, CharSequence, SecureRandom)} is specific to the format. Everything else works on an {@link UnlockedVault} and therefore for UVF as well; see
 * {@link UvfExample} for the alternative, in which shortening is a storage layer of its own.
 */
public final class Cvf8Example {

	private final Path vaultDir;
	private final UnlockedVault vault;
	private final NameShortener shortener;

	/**
	 * @param vaultDir The vault's root directory
	 * @param vault The unlocked vault stored in {@code vaultDir}
	 */
	public Cvf8Example(Path vaultDir, UnlockedVault vault) {
		this.vaultDir = vaultDir;
		this.vault = vault;
		this.shortener = vault.nameShortener();
	}

	/**
	 * Creates a vault: {@code masterkey.cryptomator}, {@code vault.cryptomator} and the root directory.
	 *
	 * @param vaultDir An empty directory
	 * @param passphrase Protects the masterkey file
	 * @param csprng Source of randomness
	 * @return The unlocked vault
	 * @throws IOException If writing fails
	 */
	public static Cvf8UnlockedVault createVault(Path vaultDir, CharSequence passphrase, SecureRandom csprng) throws IOException {
		try (CvfMasterkey masterkey = CvfMasterkey.generate(csprng)) {
			new MasterkeyFileAccess(new byte[0], csprng).persist(masterkey, vaultDir.resolve("masterkey.cryptomator"), passphrase);
			Cvf8UnlockedVault vault = Cvf8UnlockedVault.create(masterkey, 220, csprng); // ciphertext names with more than 220 chars get shortened
			Cvf8Example example = new Cvf8Example(vaultDir, vault);
			example.write(vault.configFileName(), vault.serializeConfig());
			vault.rootDirectory().writeMetadataBackup(example::write); // d/XX/YYY…/dirid.c9r
			return vault;
		}
	}

	/**
	 * @param parent The directory to create the file in
	 * @param cleartextName The file's name
	 * @param cleartext The file's contents
	 * @throws IOException If writing fails
	 */
	public void writeFile(VaultDirectory parent, String cleartextName, byte[] cleartext) throws IOException {
		VaultNode node = parent.encryptName(cleartextName);
		ShortenedVaultNode shortened = shortener.shorten(node.name()); // null unless the ciphertext name exceeds the threshold
		String contentsFile = node.name();
		if (shortened != null) {
			write(parent.dirPath() + "/" + shortened.sidecarFile(), shortened.sidecarContents()); // <hash>.c9s/name.c9s
			contentsFile = shortened.contentsFile(); // <hash>.c9s/contents.c9r
		}
		write(parent.dirPath() + "/" + contentsFile, vault.encryptFile(cleartext));
	}

	/**
	 * @param parent The directory containing the file
	 * @param cleartextName The file's name
	 * @return The file's contents
	 * @throws IOException If reading fails, e.g. because there is no such file
	 */
	public byte[] readFile(VaultDirectory parent, String cleartextName) throws IOException {
		VaultNode node = parent.encryptName(cleartextName);
		ShortenedVaultNode shortened = shortener.shorten(node.name());
		String contentsFile = shortened != null ? shortened.contentsFile() : node.name();
		return vault.decryptFile(read(parent.dirPath() + "/" + contentsFile));
	}

	/**
	 * @param parent The directory to create the subdirectory in
	 * @param cleartextName The subdirectory's name
	 * @return The new directory
	 * @throws IOException If writing fails
	 */
	public VaultDirectory createDirectory(VaultDirectory parent, String cleartextName) throws IOException {
		VaultNode node = parent.encryptName(cleartextName);
		ShortenedVaultNode shortened = shortener.shorten(node.name());
		if (shortened != null) {
			write(parent.dirPath() + "/" + shortened.sidecarFile(), shortened.sidecarContents());
			node = shortened; // a VaultNode whose dirFile() points below the shortened name
		}
		VaultDirectory child = vault.newDirectory();
		parent.createDirectory(node, child, this::write); // <name>/dir.c9r and the child's d/XX/YYY…/dirid.c9r
		return child;
	}

	/**
	 * @param parent The directory containing the subdirectory
	 * @param cleartextName The subdirectory's name
	 * @return The subdirectory
	 * @throws IOException If reading fails, e.g. because there is no such directory
	 */
	public VaultDirectory directory(VaultDirectory parent, String cleartextName) throws IOException {
		VaultNode node = parent.encryptName(cleartextName);
		ShortenedVaultNode shortened = shortener.shorten(node.name());
		return parent.directory(shortened != null ? shortened : node, this::read);
	}

	/**
	 * @param dir The directory to list
	 * @return The cleartext names of the directory's children
	 * @throws IOException If reading fails
	 */
	public List<String> list(VaultDirectory dir) throws IOException {
		List<String> cleartextNames = new ArrayList<>();
		try (DirectoryStream<Path> entries = Files.newDirectoryStream(vaultDir.resolve(dir.dirPath()))) {
			for (Path entry : entries) {
				String entryName = entry.getFileName().toString();
				if (shortener.isSidecar(entryName)) {
					continue; // never the case for CVF8, which keeps the sidecar inside the entry; UVF: <hash>.original.uvf
				}
				try {
					String ciphertextName = entryName;
					if (shortener.isShortened(entryName)) {
						byte[] sidecar = read(dir.dirPath() + "/" + shortener.sidecarFile(entryName));
						ciphertextName = shortener.unshorten(entryName, sidecar); // verifies that the sidecar belongs to this entry
					}
					cleartextNames.add(dir.decryptName(ciphertextName));
				} catch (NoSuchFileException | AuthenticationFailedException | IllegalArgumentException e) {
					// skip: sidecar missing or not matching, not a node (dirid.c9r) or an unauthentic name
				}
			}
		}
		return cleartextNames;
	}

	private byte[] read(String relPath) throws IOException {
		return Files.readAllBytes(vaultDir.resolve(relPath));
	}

	private void write(String relPath, byte[] contents) throws IOException {
		Path file = vaultDir.resolve(relPath);
		Files.createDirectories(file.getParent());
		Files.write(file, contents);
	}

}
