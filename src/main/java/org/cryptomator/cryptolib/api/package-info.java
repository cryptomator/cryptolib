/**
 * High-level encryption library used in Cryptomator.
 * <p>
 * Example Usage:
 * 
 * <pre>
 * // Define a pepper used during JSON serialization:
 * MasterkeyFileAccess masterkeyFileAccess = new MasterkeyFileAccess(pepper, csprng);
 *
 * // Create new masterkey and safe it to a file:
 * SecureRandom csprng = SecureRandom.getInstanceStrong();
 * Masterkey masterkey = {@link org.cryptomator.cryptolib.api.Masterkey#generate(java.security.SecureRandom) Masterkey.generate(csprng)};
 * {@link org.cryptomator.cryptolib.common.MasterkeyFileAccess#persist(org.cryptomator.cryptolib.api.PerpetualMasterkey, java.nio.file.Path, java.lang.CharSequence) masterkeyFileAccess.persist(masterkey, path, passphrase)};
 *
 * // Load a masterkey from a file:
 * Masterkey masterkey = {@link org.cryptomator.cryptolib.common.MasterkeyFileAccess#load(java.nio.file.Path, java.lang.CharSequence) masterkeyFileAccess.load(path, passphrase)};
 *
 * // Create new cryptor:
 * {@link org.cryptomator.cryptolib.api.Cryptor Cryptor} cryptor = {@link org.cryptomator.cryptolib.api.CryptorProvider#forScheme(org.cryptomator.cryptolib.api.CryptorProvider.Scheme) CryptorProvider.forScheme(SIV_GCM)}.{@link org.cryptomator.cryptolib.api.CryptorProvider#provide(org.cryptomator.cryptolib.api.Masterkey, java.security.SecureRandom) provide(masterkey, csprng)};
 *
 * // Each directory needs a (relatively) unique ID, which affects the encryption/decryption of child names:
 * String uniqueIdOfDirectory = UUID.randomUUID().toString();
 *
 * // Encrypt and decrypt file name:
 * String cleartextFileName = "foo.txt";
 * String encryptedName = cryptor.{@link org.cryptomator.cryptolib.api.Cryptor#fileNameCryptor() fileNameCryptor()}.{@link org.cryptomator.cryptolib.api.FileNameCryptor#encryptFilename(com.google.common.io.BaseEncoding, String, byte[][])  encryptFilename(base32, cleartextFileName, uniqueIdOfDirectory.getBytes())};
 * String decryptedName = cryptor.fileNameCryptor().{@link org.cryptomator.cryptolib.api.FileNameCryptor#decryptFilename(com.google.common.io.BaseEncoding, String, byte[][])  decryptFilename(base32, encryptedName, uniqueIdOfDirectory.getBytes())};
 *
 * // Encrypt file contents:
 * ByteBuffer plaintext = ...;
 * SeekableByteChannel ciphertextOut = ...;
 * try (WritableByteChannel ch = new {@link org.cryptomator.cryptolib.common.EncryptingWritableByteChannel EncryptingWritableByteChannel}(ciphertextOut, cryptor)) {
 * 	ch.write(plaintext);
 * }
 *
 * // Decrypt file contents:
 * ReadableByteChannel ciphertextIn = ...;
 * try (ReadableByteChannel ch = new {@link org.cryptomator.cryptolib.common.DecryptingReadableByteChannel DecryptingReadableByteChannel}(ciphertextOut, cryptor, true)) {
 * 	ch.read(plaintext);
 * }
 * </pre>
 */
package org.cryptomator.cryptolib.api;
