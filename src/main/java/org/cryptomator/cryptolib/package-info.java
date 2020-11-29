/**
 * High-level encryption library used in Cryptomator.
 * <p>
 * Example Usage:
 * 
 * <pre>
 * // Create new masterkey and safe it to a file:
 * SecureRandom csprng = SecureRandom.getInstanceStrong();
 * Masterkey masterkey = {@link org.cryptomator.cryptolib.api.Masterkey#createNew(java.security.SecureRandom) Masterkey.createNew(csprng)};
 * byte[] json = {@link org.cryptomator.cryptolib.common.MasterkeyFile#lock(org.cryptomator.cryptolib.api.Masterkey, java.lang.CharSequence, byte[], int, java.security.SecureRandom) MasterkeyFile.lock(masterkey, passphrase, pepper, vaultVersion, csprng)};
 * Files.write(path, json);
 *
 * // Load a masterkey from a file:
 * MasterkeyFileLoader loader = {@link org.cryptomator.cryptolib.common.MasterkeyFile#withContentFromFile(java.nio.file.Path) MasterkeyFile.withContentsFromFile(path)}.{@link org.cryptomator.cryptolib.common.MasterkeyFile#unlock(java.lang.CharSequence, byte[], java.util.Optional) unlock(passphrase, pepper, Optional.of(vaultVersion))};
 * Masterkey masterkey = loader.load(MasterkeyFileLoader.KEY_ID);
 *
 * // Create new cryptor:
 * {@link org.cryptomator.cryptolib.api.Cryptor Cryptor} cryptor = {@link org.cryptomator.cryptolib.Cryptors#version1(java.security.SecureRandom) Cryptors.version1(SecureRandom.getInstanceStrong())}.{@link org.cryptomator.cryptolib.api.CryptorProvider#withKey(org.cryptomator.cryptolib.api.Masterkey) withKey(masterkey)};
 *
 * // Each directory needs a (relatively) unique ID, which affects the encryption/decryption of child names:
 * String uniqueIdOfDirectory = UUID.randomUUID().toString();
 *
 * // Encrypt and decrypt file name:
 * String cleartextFileName = "foo.txt";
 * String encryptedName = cryptor.{@link org.cryptomator.cryptolib.api.Cryptor#fileNameCryptor() fileNameCryptor()}.{@link org.cryptomator.cryptolib.api.FileNameCryptor#encryptFilename(String, byte[][])  encryptFilename(cleartextFileName, uniqueIdOfDirectory.getBytes())};
 * String decryptedName = cryptor.fileNameCryptor().{@link org.cryptomator.cryptolib.api.FileNameCryptor#decryptFilename(String, byte[][])  decryptFilename(encryptedName, uniqueIdOfDirectory.getBytes())};
 *
 * // Encrypt file contents:
 * ByteBuffer plaintext = ...;
 * SeekableByteChannel ciphertextOut = ...;
 * try (WritableByteChannel ch = new {@link org.cryptomator.cryptolib.EncryptingWritableByteChannel EncryptingWritableByteChannel}(ciphertextOut, cryptor)) {
 * 	ch.write(plaintext);
 * }
 *
 * // Decrypt file contents:
 * ReadableByteChannel ciphertextIn = ...;
 * try (ReadableByteChannel ch = new {@link org.cryptomator.cryptolib.DecryptingReadableByteChannel DecryptingReadableByteChannel}(ciphertextOut, cryptor, true)) {
 * 	ch.read(plaintext);
 * }
 * </pre>
 */
/**
 * High-level encryption library used in Cryptomator.
 * <p>
 * Example Usage:
 *
 * <pre>
 * // Create new masterkey and safe it to a file:
 * SecureRandom csprng = SecureRandom.getInstanceStrong();
 * Masterkey masterkey = {@link org.cryptomator.cryptolib.api.Masterkey#createNew(java.security.SecureRandom) Masterkey.createNew(csprng)};
 * byte[] json = {@link org.cryptomator.cryptolib.common.MasterkeyFile#lock(org.cryptomator.cryptolib.api.Masterkey, java.lang.CharSequence, byte[], int, java.security.SecureRandom) MasterkeyFile.lock(masterkey, passphrase, pepper, vaultVersion, csprng)};
 * Files.write(path, json);
 *
 * // Load a masterkey from a file:
 * MasterkeyFileLoader loader = {@link org.cryptomator.cryptolib.common.MasterkeyFile#withContentFromFile(java.nio.file.Path) MasterkeyFile.withContentsFromFile(path)}.{@link org.cryptomator.cryptolib.common.MasterkeyFile#unlock(java.lang.CharSequence, byte[], java.util.Optional) unlock(passphrase, pepper, Optional.of(vaultVersion))};
 * Masterkey masterkey = loader.load(MasterkeyFileLoader.KEY_ID);
 *
 * // Create new cryptor:
 * {@link org.cryptomator.cryptolib.api.Cryptor Cryptor} cryptor = {@link org.cryptomator.cryptolib.Cryptors#version1(java.security.SecureRandom) Cryptors.version1(SecureRandom.getInstanceStrong())}.{@link org.cryptomator.cryptolib.api.CryptorProvider#withKey(org.cryptomator.cryptolib.api.Masterkey) withKey(masterkey)};
 * // Each directory needs a (relatively) unique ID, which affects the encryption/decryption of child names:
 * String uniqueIdOfDirectory = UUID.randomUUID().toString();
 *
 * // Encrypt and decrypt file name:
 * String cleartextFileName = "foo.txt";
 * String encryptedName = cryptor.{@link org.cryptomator.cryptolib.api.Cryptor#fileNameCryptor() fileNameCryptor()}.{@link org.cryptomator.cryptolib.api.FileNameCryptor#encryptFilename(String, byte[][])  encryptFilename(cleartextFileName, uniqueIdOfDirectory.getBytes())};
 * String decryptedName = cryptor.fileNameCryptor().{@link org.cryptomator.cryptolib.api.FileNameCryptor#decryptFilename(String, byte[][])  decryptFilename(encryptedName, uniqueIdOfDirectory.getBytes())};
 *
 * // Encrypt file contents:
 * ByteBuffer plaintext = ...;
 * SeekableByteChannel ciphertextOut = ...;
 * try (WritableByteChannel ch = new {@link org.cryptomator.cryptolib.EncryptingWritableByteChannel EncryptingWritableByteChannel}(ciphertextOut, cryptor)) {
 * 	ch.write(plaintext);
 * }
 *
 * // Decrypt file contents:
 * ReadableByteChannel ciphertextIn = ...;
 * try (ReadableByteChannel ch = new {@link org.cryptomator.cryptolib.DecryptingReadableByteChannel DecryptingReadableByteChannel}(ciphertextOut, cryptor, true)) {
 * 	ch.read(plaintext);
 * }
 * </pre>
 */
package org.cryptomator.cryptolib;
