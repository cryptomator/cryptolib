/**
 * High-level encryption library used in Cryptomator: everything about a vault except the file I/O.
 * <p>
 * Reading and writing of files is left to the caller; cryptolib operates on {@code byte[]}, {@link java.nio.ByteBuffer}, {@link String}, channels and streams, and reads or writes small
 * metadata files only through the {@link org.cryptomator.cryptolib.api.VaultReader} / {@link org.cryptomator.cryptolib.api.VaultWriter} callbacks. Both the Cryptomator Vault Format 8
 * and the Unified Vault Format are supported behind the same API.
 * <p>
 * Example usage (see the README for more):
 *
 * <pre>{@code
 * VaultReader reader = relPath -> Files.readAllBytes(vaultDir.resolve(relPath));
 * VaultWriter writer = (relPath, bytes) -> {
 *     Path file = vaultDir.resolve(relPath);
 *     Files.createDirectories(file.getParent());
 *     Files.write(file, bytes);
 * };
 *
 * // Open an existing vault:
 * LockedVault locked = LockedVault.parse(Files.readAllBytes(configPath)); // vault.cryptomator or vault.uvf
 * UnlockedVault vault;
 * if (locked instanceof Cvf8LockedVault) {
 *     vault = ((Cvf8LockedVault) locked).unlock(masterkeyLoader, csprng);
 * } else {
 *     UvfLockedVault uvf = (UvfLockedVault) locked;
 *     vault = uvf.unlock(passphrase, csprng); // or unlock(memberKey, csprng), see uvf.keyEncryptionKid()
 * }
 *
 * // List the root directory:
 * VaultDirectory root = vault.rootDirectory();
 * try (DirectoryStream<Path> entries = Files.newDirectoryStream(vaultDir.resolve(root.dirPath()))) {
 *     for (Path entry : entries) {
 *         String cleartextName = root.decryptName(entry.getFileName().toString(), reader);
 *     }
 * }
 *
 * // Create a subdirectory:
 * root.encryptName("Documents").createDirectory(vault.newDirectory(), writer);
 *
 * // Encrypt a file:
 * try (WritableByteChannel ch = vault.encryptingChannel(Files.newByteChannel(ciphertextPath, CREATE_NEW, WRITE))) {
 *     ch.write(cleartext);
 * }
 *
 * // Random access to a file:
 * try (FileChannel ch = FileChannel.open(ciphertextPath, READ, WRITE); VaultFile file = vault.openFile(readHeader(ch), ch.size())) {
 *     file.read(position, buffer, ch::read);
 *     file.write(position, data, ch::read, ch::write);
 * }
 * }</pre>
 */
package org.cryptomator.cryptolib.api;
