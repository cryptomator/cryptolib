package org.cryptomator.cryptolib.common;

import com.google.common.base.Preconditions;
import org.cryptomator.cryptolib.api.InvalidPassphraseException;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.api.MasterkeyLoadingFailedException;
import org.cryptomator.cryptolib.api.PerpetualMasterkey;

import javax.crypto.Mac;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Writer;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.Arrays;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Allow loading and persisting of {@link Masterkey masterkeys} from and to encrypted json files.
 * <p>
 * Requires a passphrase for derivation of a KEK.
 *
 * <pre>
 * 	MasterkeyFileAccess masterkeyFileAccess = new MasterkeyFileAccess(pepper, csprng);
 * 	try (Masterkey masterkey = masterkeyFileAccess.load(path, passphrase) {
 * 		// use masterkey
 *  }
 * </pre>
 */
public class MasterkeyFileAccess {

	private static final int DEFAULT_MASTERKEY_FILE_VERSION = 999; // legacy field. dropped with vault format 8
	private static final int DEFAULT_SCRYPT_SALT_LENGTH = 8;
	private static final int DEFAULT_SCRYPT_COST_PARAM = 1 << 15; // 2^15
	private static final int DEFAULT_SCRYPT_BLOCK_SIZE = 8;

	private final byte[] pepper;
	private final SecureRandom csprng;

	public MasterkeyFileAccess(byte[] pepper, SecureRandom csprng) {
		this.pepper = pepper;
		this.csprng = csprng;
	}

	/**
	 * Parses the given masterkey file contents and returns the alleged vault version without verifying the version MAC.
	 *
	 * @param masterkey The file contents of a masterkey file.
	 * @return The (unverified) vault version
	 * @throws IOException In case of errors, such as unparseable JSON.
	 * @deprecated Starting with vault format 8, the vault version is no longer stored inside the masterkey file.
	 */
	@Deprecated
	public static int readAllegedVaultVersion(byte[] masterkey) throws IOException {
		try (ByteArrayInputStream in = new ByteArrayInputStream(masterkey);
			 Reader reader = new InputStreamReader(in, UTF_8)) {
			MasterkeyFile parsedFile = MasterkeyFile.read(reader);
			return parsedFile.version;
		}
	}

	/**
	 * Reencrypts a masterkey with a new passphrase.
	 *
	 * @param masterkey     The original JSON representation of the masterkey
	 * @param oldPassphrase The old passphrase
	 * @param newPassphrase The new passphrase
	 * @return A JSON representation of the masterkey, now encrypted with <code>newPassphrase</code>
	 * @throws IOException                If failing to read, parse or write JSON
	 * @throws InvalidPassphraseException If the wrong <code>oldPassphrase</code> has been supplied for the <code>masterkey</code>
	 */
	public byte[] changePassphrase(byte[] masterkey, CharSequence oldPassphrase, CharSequence newPassphrase) throws IOException, InvalidPassphraseException {
		try (ByteArrayInputStream in = new ByteArrayInputStream(masterkey);
			 ByteArrayOutputStream out = new ByteArrayOutputStream()) {
			changePassphrase(in, out, oldPassphrase, newPassphrase);
			return out.toByteArray();
		}
	}

	public void changePassphrase(InputStream oldIn, OutputStream newOut, CharSequence oldPassphrase, CharSequence newPassphrase) throws IOException, InvalidPassphraseException {
		try (Reader reader = new InputStreamReader(oldIn, UTF_8);
			 Writer writer = new OutputStreamWriter(newOut, UTF_8)) {
			MasterkeyFile original = MasterkeyFile.read(reader);
			MasterkeyFile updated = changePassphrase(original, oldPassphrase, newPassphrase);
			updated.write(writer);
		}
	}

	// visible for testing
	MasterkeyFile changePassphrase(MasterkeyFile masterkey, CharSequence oldPassphrase, CharSequence newPassphrase) throws InvalidPassphraseException {
		try (PerpetualMasterkey key = unlock(masterkey, oldPassphrase)) {
			return lock(key, newPassphrase, masterkey.version, masterkey.scryptCostParam);
		}
	}

	/**
	 * Loads the JSON contents from the given file and derives a KEK from the given passphrase to
	 * unwrap the contained keys.
	 *
	 * @param filePath   Which file to load
	 * @param passphrase The passphrase used during key derivation
	 * @return A new masterkey. Should be used in a try-with-resource statement.
	 * @throws InvalidPassphraseException      If the provided passphrase can not be used to unwrap the stored keys.
	 * @throws MasterkeyLoadingFailedException If reading the masterkey file fails
	 */
	public PerpetualMasterkey load(Path filePath, CharSequence passphrase) throws MasterkeyLoadingFailedException {
		try (InputStream in = Files.newInputStream(filePath, StandardOpenOption.READ)) {
			return load(in, passphrase);
		} catch (IOException e) {
			throw new MasterkeyLoadingFailedException("I/O error", e);
		}
	}

	public PerpetualMasterkey load(InputStream in, CharSequence passphrase) throws IOException {
		try (Reader reader = new InputStreamReader(in, UTF_8)) {
			MasterkeyFile parsedFile = MasterkeyFile.read(reader);
			if (!parsedFile.isValid()) {
				throw new IOException("Invalid key file");
			} else {
				return unlock(parsedFile, passphrase);
			}
		}
	}

	// visible for testing
	PerpetualMasterkey unlock(MasterkeyFile parsedFile, CharSequence passphrase) throws InvalidPassphraseException {
		Preconditions.checkNotNull(parsedFile);
		Preconditions.checkArgument(parsedFile.isValid(), "Invalid masterkey file");
		Preconditions.checkNotNull(passphrase);

		try (DestroyableSecretKey kek = scrypt(passphrase, parsedFile.scryptSalt, pepper, parsedFile.scryptCostParam, parsedFile.scryptBlockSize);
			 DestroyableSecretKey encKey = AesKeyWrap.unwrap(kek, parsedFile.encMasterKey, PerpetualMasterkey.ENC_ALG);
			 DestroyableSecretKey macKey = AesKeyWrap.unwrap(kek, parsedFile.macMasterKey, PerpetualMasterkey.MAC_ALG)) {
			return Masterkey.from(encKey, macKey);
		} catch (InvalidKeyException e) {
			throw new InvalidPassphraseException();
		}
	}

	/**
	 * Derives a KEK from the given passphrase and wraps the key material from <code>masterkey</code>.
	 * Then serializes the encrypted keys as well as used key derivation parameters into a JSON representation
	 * that will be stored at the given filePath.
	 *
	 * @param masterkey  The key to protect
	 * @param filePath   Where to store the file (gets overwritten, parent dir must exist)
	 * @param passphrase The passphrase used during key derivation
	 * @throws IOException When unable to write to the given file
	 */
	public void persist(PerpetualMasterkey masterkey, Path filePath, CharSequence passphrase) throws IOException {
		persist(masterkey, filePath, passphrase, DEFAULT_MASTERKEY_FILE_VERSION);
	}

	public void persist(PerpetualMasterkey masterkey, Path filePath, CharSequence passphrase, @Deprecated int vaultVersion) throws IOException {
		Path tmpFilePath = filePath.resolveSibling(filePath.getFileName().toString() + ".tmp");
		try (OutputStream out = Files.newOutputStream(tmpFilePath, StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW)) {
			persist(masterkey, out, passphrase, vaultVersion);
		}
		Files.move(tmpFilePath, filePath, StandardCopyOption.REPLACE_EXISTING);
	}

	public void persist(PerpetualMasterkey masterkey, OutputStream out, CharSequence passphrase, @Deprecated int vaultVersion) throws IOException {
		persist(masterkey, out, passphrase, vaultVersion, DEFAULT_SCRYPT_COST_PARAM);
	}

	// visible for testing
	void persist(PerpetualMasterkey masterkey, OutputStream out, CharSequence passphrase, @Deprecated int vaultVersion, int scryptCostParam) throws IOException {
		Preconditions.checkArgument(!masterkey.isDestroyed(), "masterkey has been destroyed");

		MasterkeyFile fileContent = lock(masterkey, passphrase, vaultVersion, scryptCostParam);
		try (Writer writer = new OutputStreamWriter(out, UTF_8)) {
			fileContent.write(writer);
		}
	}

	// visible for testing
	MasterkeyFile lock(PerpetualMasterkey masterkey, CharSequence passphrase, int vaultVersion, int scryptCostParam) {
		Preconditions.checkNotNull(masterkey);
		Preconditions.checkNotNull(passphrase);
		Preconditions.checkArgument(!masterkey.isDestroyed(), "masterkey has been destroyed");

		final byte[] salt = new byte[DEFAULT_SCRYPT_SALT_LENGTH];
		csprng.nextBytes(salt);
		try (DestroyableSecretKey kek = scrypt(passphrase, salt, pepper, scryptCostParam, DEFAULT_SCRYPT_BLOCK_SIZE);
			 DestroyableSecretKey macKey = masterkey.getMacKey();
			 ObjectPool.Lease<Mac> mac = MacSupplier.HMAC_SHA256.keyed(macKey)) {
			final byte[] versionMac = mac.get().doFinal(ByteBuffer.allocate(Integer.SIZE / Byte.SIZE).putInt(vaultVersion).array());
			MasterkeyFile result = new MasterkeyFile();
			result.version = vaultVersion;
			result.versionMac = versionMac;
			result.scryptSalt = salt;
			result.scryptCostParam = scryptCostParam;
			result.scryptBlockSize = DEFAULT_SCRYPT_BLOCK_SIZE;
			result.encMasterKey = AesKeyWrap.wrap(kek, masterkey.getEncKey());
			result.macMasterKey = AesKeyWrap.wrap(kek, masterkey.getMacKey());
			return result;
		}
	}

	private static DestroyableSecretKey scrypt(CharSequence passphrase, byte[] salt, byte[] pepper, int costParam, int blockSize) {
		byte[] saltAndPepper = new byte[salt.length + pepper.length];
		System.arraycopy(salt, 0, saltAndPepper, 0, salt.length);
		System.arraycopy(pepper, 0, saltAndPepper, salt.length, pepper.length);
		byte[] kekBytes = Scrypt.scrypt(passphrase, saltAndPepper, costParam, blockSize, PerpetualMasterkey.SUBKEY_LEN_BYTES);
		try {
			return new DestroyableSecretKey(kekBytes, PerpetualMasterkey.ENC_ALG);
		} finally {
			Arrays.fill(kekBytes, (byte) 0x00);
		}
	}


}
