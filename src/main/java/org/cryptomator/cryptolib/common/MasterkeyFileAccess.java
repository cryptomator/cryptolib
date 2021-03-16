package org.cryptomator.cryptolib.common;

import com.google.common.base.Preconditions;
import com.google.common.io.BaseEncoding;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonIOException;
import com.google.gson.JsonParseException;
import com.google.gson.TypeAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;
import org.cryptomator.cryptolib.api.InvalidPassphraseException;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.api.MasterkeyLoader;
import org.cryptomator.cryptolib.api.MasterkeyLoadingFailedException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.Arrays;

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
	private static final Gson GSON = new GsonBuilder() //
			.setPrettyPrinting() //
			.disableHtmlEscaping() //
			.registerTypeHierarchyAdapter(byte[].class, new MasterkeyFileAccess.ByteArrayJsonAdapter()) //
			.create();

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
			 Reader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
			MasterkeyFile parsedFile = GSON.fromJson(reader, MasterkeyFile.class);
			return parsedFile.version;
		} catch (JsonParseException e) {
			throw new IOException("Unreadable JSON", e);
		} catch (IllegalArgumentException e) {
			throw new IOException("Invalid JSON content", e);
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
		try (Reader reader = new InputStreamReader(oldIn, StandardCharsets.UTF_8);
			 Writer writer = new OutputStreamWriter(newOut, StandardCharsets.UTF_8)) {
			MasterkeyFile original = GSON.fromJson(reader, MasterkeyFile.class);
			MasterkeyFile updated = changePassphrase(original, oldPassphrase, newPassphrase);
			GSON.toJson(updated, writer);
		} catch (JsonParseException e) {
			throw new IOException("Unreadable JSON", e);
		} catch (IllegalArgumentException e) {
			throw new IOException("Invalid JSON content", e);
		}
	}

	// visible for testing
	MasterkeyFile changePassphrase(MasterkeyFile masterkey, CharSequence oldPassphrase, CharSequence newPassphrase) throws InvalidPassphraseException {
		try (Masterkey key = unlock(masterkey, oldPassphrase)) {
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
	public Masterkey load(Path filePath, CharSequence passphrase) throws MasterkeyLoadingFailedException {
		try (InputStream in = Files.newInputStream(filePath, StandardOpenOption.READ)) {
			return load(in, passphrase);
		} catch (IOException e) {
			throw new MasterkeyLoadingFailedException("I/O error", e);
		}
	}

	public Masterkey load(InputStream in, CharSequence passphrase) throws MasterkeyLoadingFailedException, IOException {
		try (Reader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
			MasterkeyFile parsedFile = GSON.fromJson(reader, MasterkeyFile.class);
			if (parsedFile == null || !parsedFile.isValid()) {
				throw new JsonParseException("Invalid key file");
			} else {
				return unlock(parsedFile, passphrase);
			}
		} catch (JsonParseException e) {
			throw new MasterkeyLoadingFailedException("Unreadable JSON", e);
		} catch (IllegalArgumentException e) {
			throw new MasterkeyLoadingFailedException("Invalid JSON content", e);
		}
	}

	// visible for testing
	Masterkey unlock(MasterkeyFile parsedFile, CharSequence passphrase) throws InvalidPassphraseException {
		Preconditions.checkNotNull(parsedFile);
		Preconditions.checkArgument(parsedFile.isValid(), "Invalid masterkey file");
		Preconditions.checkNotNull(passphrase);

		byte[] encKey = new byte[0], macKey = new byte[0], combined = new byte[0];
		try (DestroyableSecretKey kek = scrypt(passphrase, parsedFile.scryptSalt, pepper, parsedFile.scryptCostParam, parsedFile.scryptBlockSize)) {
			encKey = AesKeyWrap.unwrap(kek, parsedFile.encMasterKey, Masterkey.ENC_ALG).getEncoded();
			macKey = AesKeyWrap.unwrap(kek, parsedFile.macMasterKey, Masterkey.MAC_ALG).getEncoded();
			combined = new byte[encKey.length + macKey.length];
			System.arraycopy(encKey, 0, combined, 0, encKey.length);
			System.arraycopy(macKey, 0, combined, encKey.length, macKey.length);
			return new Masterkey(combined);
		} catch (InvalidKeyException e) {
			throw new InvalidPassphraseException();
		} finally {
			Arrays.fill(encKey, (byte) 0x00);
			Arrays.fill(macKey, (byte) 0x00);
			Arrays.fill(combined, (byte) 0x00);
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
	public void persist(Masterkey masterkey, Path filePath, CharSequence passphrase) throws IOException {
		persist(masterkey, filePath, passphrase, DEFAULT_MASTERKEY_FILE_VERSION);
	}

	public void persist(Masterkey masterkey, Path filePath, CharSequence passphrase, @Deprecated int vaultVersion) throws IOException {
		Path tmpFilePath = filePath.resolveSibling(filePath.getFileName().toString() + ".tmp");
		try (OutputStream out = Files.newOutputStream(tmpFilePath, StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW)) {
			persist(masterkey, out, passphrase, vaultVersion);
		}
		Files.move(tmpFilePath, filePath, StandardCopyOption.REPLACE_EXISTING);
	}

	public void persist(Masterkey masterkey, OutputStream out, CharSequence passphrase, @Deprecated int vaultVersion) throws IOException {
		persist(masterkey, out, passphrase, vaultVersion, DEFAULT_SCRYPT_COST_PARAM);
	}

	// visible for testing
	void persist(Masterkey masterkey, OutputStream out, CharSequence passphrase, @Deprecated int vaultVersion, int scryptCostParam) throws IOException {
		Preconditions.checkArgument(!masterkey.isDestroyed(), "masterkey has been destroyed");

		MasterkeyFile fileContent = lock(masterkey, passphrase, vaultVersion, scryptCostParam);
		try (Writer writer = new OutputStreamWriter(out, StandardCharsets.UTF_8)) {
			GSON.toJson(fileContent, writer);
		} catch (JsonIOException e) {
			throw new IOException(e);
		}
	}

	// visible for testing
	MasterkeyFile lock(Masterkey masterkey, CharSequence passphrase, int vaultVersion, int scryptCostParam) {
		Preconditions.checkNotNull(masterkey);
		Preconditions.checkNotNull(passphrase);
		Preconditions.checkArgument(!masterkey.isDestroyed(), "masterkey has been destroyed");

		final byte[] salt = new byte[DEFAULT_SCRYPT_SALT_LENGTH];
		csprng.nextBytes(salt);
		try (DestroyableSecretKey kek = scrypt(passphrase, salt, pepper, scryptCostParam, DEFAULT_SCRYPT_BLOCK_SIZE)) {
			final Mac mac = MacSupplier.HMAC_SHA256.withKey(masterkey.getMacKey());
			final byte[] versionMac = mac.doFinal(ByteBuffer.allocate(Integer.SIZE / Byte.SIZE).putInt(vaultVersion).array());
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

	/**
	 * Creates a {@link MasterkeyLoader} able to load keys from masterkey JSON files using the same pepper as <code>this</code>.
	 *
	 * @param vaultRoot The path to a vault for which a masterkey should be loaded.
	 * @param context   A context providing information required by the key loader.
	 * @return A new masterkey loader.
	 */
	public MasterkeyFileLoader keyLoader(Path vaultRoot, MasterkeyFileLoaderContext context) {
		return new MasterkeyFileLoader(vaultRoot, this, context);
	}

	private static DestroyableSecretKey scrypt(CharSequence passphrase, byte[] salt, byte[] pepper, int costParam, int blockSize) {
		byte[] saltAndPepper = new byte[salt.length + pepper.length];
		System.arraycopy(salt, 0, saltAndPepper, 0, salt.length);
		System.arraycopy(pepper, 0, saltAndPepper, salt.length, pepper.length);
		byte[] kekBytes = Scrypt.scrypt(passphrase, saltAndPepper, costParam, blockSize, Masterkey.SUBKEY_LEN_BYTES);
		try {
			return new DestroyableSecretKey(kekBytes, Masterkey.ENC_ALG);
		} finally {
			Arrays.fill(kekBytes, (byte) 0x00);
		}
	}

	// visible for testing
	static class MasterkeyFile {

		@SerializedName("version")
		int version;

		@SerializedName("scryptSalt")
		byte[] scryptSalt;

		@SerializedName("scryptCostParam")
		int scryptCostParam;

		@SerializedName("scryptBlockSize")
		int scryptBlockSize;

		@SerializedName("primaryMasterKey")
		byte[] encMasterKey;

		@SerializedName("hmacMasterKey")
		byte[] macMasterKey;

		@SerializedName("versionMac")
		byte[] versionMac;

		private boolean isValid() {
			return version != 0
					&& scryptSalt != null
					&& scryptCostParam > 1
					&& scryptBlockSize > 0
					&& encMasterKey != null
					&& macMasterKey != null
					&& versionMac != null;
		}

	}

	private static class ByteArrayJsonAdapter extends TypeAdapter<byte[]> {

		private static final BaseEncoding BASE64 = BaseEncoding.base64();

		@Override
		public void write(JsonWriter writer, byte[] value) throws IOException {
			if (value == null) {
				writer.nullValue();
			} else {
				writer.value(BASE64.encode(value));
			}
		}

		@Override
		public byte[] read(JsonReader reader) throws IOException {
			if (reader.peek() == JsonToken.NULL) {
				reader.nextNull();
				return null;
			} else {
				return BASE64.decode(reader.nextString());
			}
		}
	}

}
