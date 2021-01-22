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
import javax.crypto.spec.SecretKeySpec;
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
import java.util.function.Function;

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
			 ByteArrayOutputStream out = new ByteArrayOutputStream();
			 Reader reader = new InputStreamReader(in, StandardCharsets.UTF_8);
			 Writer writer = new OutputStreamWriter(out, StandardCharsets.UTF_8)) {
			MasterkeyFile original = GSON.fromJson(reader, MasterkeyFile.class);
			MasterkeyFile updated = changePassphrase(original, oldPassphrase, newPassphrase);
			GSON.toJson(updated, writer);
			return out.toByteArray();
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
	 * @throws MasterkeyLoadingFailedException
	 */
	public Masterkey load(Path filePath, CharSequence passphrase) throws MasterkeyLoadingFailedException {
		try (InputStream in = Files.newInputStream(filePath, StandardOpenOption.READ)) {
			return load(in, passphrase);
		} catch (IOException e) {
			throw new MasterkeyLoadingFailedException("I/O error", e);
		}
	}

	Masterkey load(InputStream in, CharSequence passphrase) throws MasterkeyLoadingFailedException, IOException {
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

		SecretKey kek = scrypt(passphrase, parsedFile.scryptSalt, pepper, parsedFile.scryptCostParam, parsedFile.scryptBlockSize);
		try {
			SecretKey encKey = AesKeyWrap.unwrap(kek, parsedFile.encMasterKey, Masterkey.ENC_ALG);
			SecretKey macKey = AesKeyWrap.unwrap(kek, parsedFile.macMasterKey, Masterkey.MAC_ALG);
			return new Masterkey(encKey, macKey);
		} catch (InvalidKeyException e) {
			throw new InvalidPassphraseException();
		} finally {
			Destroyables.destroySilently(kek);
		}
	}

	/**
	 * Derives a KEK from the given passphrase and wraps the key material from <code>masterkey</code>.
	 * Then serializes the encrypted keys as well as used key derivation parameters into a JSON representation
	 * that will be stored at the given filePath.
	 *
	 * @param masterkey    The key to protect
	 * @param filePath     Where to store the file (gets overwritten, parent dir must exist)
	 * @param passphrase   The passphrase used during key derivation
	 * @param vaultVersion The vault version that should be stored in this masterkey file (for downwards compatibility)
	 * @throws IOException When unable to write to the given file
	 */
	public void persist(Masterkey masterkey, Path filePath, CharSequence passphrase, int vaultVersion) throws IOException {
		Path tmpFilePath = filePath.resolveSibling(filePath.getFileName().toString() + ".tmp");
		try (OutputStream out = Files.newOutputStream(tmpFilePath, StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW)) {
			persist(masterkey, out, passphrase, vaultVersion);
		}
		Files.move(tmpFilePath, filePath, StandardCopyOption.REPLACE_EXISTING);
	}

	void persist(Masterkey masterkey, OutputStream out, CharSequence passphrase, int vaultVersion) throws IOException {
		Preconditions.checkArgument(!masterkey.isDestroyed(), "masterkey has been destroyed");

		MasterkeyFile fileContent = lock(masterkey, passphrase, vaultVersion, DEFAULT_SCRYPT_COST_PARAM);
		try (Writer writer = new OutputStreamWriter(out, StandardCharsets.UTF_8)) {
			GSON.toJson(fileContent, writer);
			writer.flush();
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
		SecretKey kek = scrypt(passphrase, salt, pepper, scryptCostParam, DEFAULT_SCRYPT_BLOCK_SIZE);
		try {
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
		} finally {
			Destroyables.destroySilently(kek);
		}
	}

	/**
	 * Creates a {@link MasterkeyLoader} able to load keys from masterkey JSON files using the same pepper as <code>this</code>.
	 *
	 * @param passphraseProvider A callback used to retrieve the passphrase used during key derivation
	 * @param <C> The type of the context to use during passphrase retrieval.
	 * @return A new masterkey loader.
	 */
	public <C extends VaultRootAwareContext> MasterkeyLoader<C> keyLoader(Function<C, CharSequence> passphraseProvider) {
		return new MasterkeyFileLoader<>(this, passphraseProvider);
	}

	private static SecretKey scrypt(CharSequence passphrase, byte[] salt, byte[] pepper, int costParam, int blockSize) {
		byte[] saltAndPepper = new byte[salt.length + pepper.length];
		System.arraycopy(salt, 0, saltAndPepper, 0, salt.length);
		System.arraycopy(pepper, 0, saltAndPepper, salt.length, pepper.length);
		byte[] kekBytes = Scrypt.scrypt(passphrase, saltAndPepper, costParam, blockSize, Masterkey.KEY_LEN_BYTES);
		try {
			return new SecretKeySpec(kekBytes, Masterkey.ENC_ALG);
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
