package org.cryptomator.cryptolib.common;

import com.google.common.base.Preconditions;
import com.google.common.io.BaseEncoding;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParseException;
import com.google.gson.TypeAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;
import org.cryptomator.cryptolib.api.CryptoException;
import org.cryptomator.cryptolib.api.InvalidPassphraseException;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.api.UnsupportedVaultFormatException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Optional;

public class MasterkeyFile {

	private static final int DEFAULT_SCRYPT_SALT_LENGTH = 8;
	private static final int DEFAULT_SCRYPT_COST_PARAM = 1 << 15; // 2^15
	private static final int DEFAULT_SCRYPT_BLOCK_SIZE = 8;
	private static final Gson GSON = new GsonBuilder() //
			.setPrettyPrinting() //
			.disableHtmlEscaping() //
			.registerTypeHierarchyAdapter(byte[].class, new ByteArrayJsonAdapter()) //
			.create();

	private final Content content;

	private MasterkeyFile(Content content) {
		Preconditions.checkArgument(content.isValid(), "Invalid content");
		this.content = content;
	}

	public static MasterkeyFile withContentFromFile(Path path) throws IOException {
		try (InputStream in = Files.newInputStream(path, StandardOpenOption.READ)) {
			return MasterkeyFile.withContent(in);
		}
	}

	public static MasterkeyFile withContent(InputStream in) throws IOException {
		try (Reader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
			Content content = GSON.fromJson(reader, Content.class);
			return new MasterkeyFile(content);
		} catch (JsonParseException e) {
			throw new IOException("Unreadable JSON", e);
		} catch (IllegalArgumentException e) {
			throw new IOException("Invalid JSON content", e);
		}
	}

	/**
	 * Derives a KEK from the given passphrase and the params from this masterkey file using scrypt and unwraps the
	 * stored encryption and MAC keys.
	 *
	 * @param passphrase           The passphrase used during key derivation
	 * @param pepper               An optional application-specific pepper added to the scrypt's salt. Can be an empty array.
	 * @param expectedVaultVersion An optional expected vault version.
	 * @return A masterkey loader that can be used to access the unwrapped keys. Should be used in a try-with-resource statement.
	 * @throws UnsupportedVaultFormatException If the expectedVaultVersion is present and does not match the cryptographically signed version stored in the masterkey file.
	 * @throws InvalidPassphraseException      If the provided passphrase can not be used to unwrap the stored keys.
	 * @throws CryptoException                 In case of any other cryptographic exceptions
	 */
	public MasterkeyFileLoader unlock(CharSequence passphrase, byte[] pepper, Optional<Integer> expectedVaultVersion) throws UnsupportedVaultFormatException, InvalidPassphraseException, CryptoException {
		boolean success = false;
		SecretKey kek = null;
		SecretKey encKey = null;
		SecretKey macKey = null;
		try {
			// derive keys:
			kek = scrypt(passphrase, content.scryptSalt, pepper, content.scryptCostParam, content.scryptBlockSize);
			macKey = AesKeyWrap.unwrap(kek, content.macMasterKey, Masterkey.MAC_ALG);
			encKey = AesKeyWrap.unwrap(kek, content.encMasterKey, Masterkey.ENC_ALG);

			// check MAC:
			if (expectedVaultVersion.isPresent()) {
				checkVaultVersion(content, macKey, expectedVaultVersion.get());
			}

			// construct key:
			success = true;
			return new MasterkeyFileLoader(encKey, macKey);
		} catch (InvalidKeyException e) {
			throw new InvalidPassphraseException();
		} finally {
			Destroyables.destroySilently(kek);
			if (!success) {
				Destroyables.destroySilently(encKey);
				Destroyables.destroySilently(macKey);
			}
		}
	}

	/**
	 * Derives a KEK from the given passphrase and wraps the key material from <code>masterkey</code>.
	 * Then serializes the encrypted keys as well as used key derivation parameters into a JSON representation
	 * that can be stored into a masterkey file.
	 *
	 * @param masterkey    The key to protect
	 * @param passphrase   The passphrase used during key derivation
	 * @param pepper       An optional application-specific pepper added to the scrypt's salt. Can be an empty array.
	 * @param vaultVersion The vault version that should be stored in this masterkey file (for downwards compatibility)
	 * @param csprng       A cryptographically secure RNG
	 * @return A JSON representation of the encrypted masterkey with its key derivation parameters.
	 */
	public static byte[] lock(Masterkey masterkey, CharSequence passphrase, byte[] pepper, int vaultVersion, SecureRandom csprng) {
		Preconditions.checkArgument(!masterkey.isDestroyed(), "masterkey has been destroyed");

		final byte[] salt = new byte[DEFAULT_SCRYPT_SALT_LENGTH];
		csprng.nextBytes(salt);
		SecretKey kek = scrypt(passphrase, salt, pepper, DEFAULT_SCRYPT_COST_PARAM, DEFAULT_SCRYPT_BLOCK_SIZE);
		try {
			final Mac mac = MacSupplier.HMAC_SHA256.withKey(masterkey.getMacKey());
			final byte[] versionMac = mac.doFinal(ByteBuffer.allocate(Integer.SIZE / Byte.SIZE).putInt(vaultVersion).array());
			Content content = new Content();
			content.version = vaultVersion;
			content.versionMac = versionMac;
			content.scryptSalt = salt;
			content.scryptCostParam = DEFAULT_SCRYPT_COST_PARAM;
			content.scryptBlockSize = DEFAULT_SCRYPT_BLOCK_SIZE;
			content.encMasterKey = AesKeyWrap.wrap(kek, masterkey.getEncKey());
			content.macMasterKey = AesKeyWrap.wrap(kek, masterkey.getMacKey());
			return GSON.toJson(content).getBytes(StandardCharsets.UTF_8);
		} finally {
			Destroyables.destroySilently(kek);
		}
	}

	/**
	 * Reencrypts a masterkey with a new passphrase.
	 *
	 * @param masterkey     The original JSON representation of the masterkey
	 * @param oldPassphrase The old passphrase
	 * @param newPassphrase The new passphrase
	 * @param pepper        An application-specific pepper added to the salt during key-derivation (if applicable)
	 * @param csprng        A cryptographically secure RNG
	 * @return A JSON representation of the masterkey, now encrypted with <code>newPassphrase</code>
	 * @throws IOException
	 * @throws InvalidPassphraseException If the wrong <code>oldPassphrase</code> has been supplied for the <code>masterkey</code>
	 * @throws CryptoException            In case of other cryptographic exceptions.
	 */
	public static byte[] changePassphrase(byte[] masterkey, CharSequence oldPassphrase, CharSequence newPassphrase, byte[] pepper, SecureRandom csprng) throws IOException, InvalidPassphraseException, CryptoException {
		MasterkeyFile orig = MasterkeyFile.withContent(new ByteArrayInputStream(masterkey));
		try (MasterkeyFileLoader loader = orig.unlock(oldPassphrase, pepper, Optional.empty());
			 Masterkey key = loader.loadKey(MasterkeyFileLoader.KEY_ID)) {
			return MasterkeyFile.lock(key, newPassphrase, pepper, orig.content.version, csprng);
		}
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

	private void checkVaultVersion(Content content, SecretKey macKey, int expectedVaultVersion) throws UnsupportedVaultFormatException {
		Mac mac = MacSupplier.HMAC_SHA256.withKey(macKey);
		byte[] expectedVaultVersionMac = mac.doFinal(ByteBuffer.allocate(Integer.SIZE / Byte.SIZE).putInt(expectedVaultVersion).array());
		if (content.versionMac == null || !MessageDigest.isEqual(expectedVaultVersionMac, content.versionMac)) {
			// attempted downgrade attack: versionMac doesn't match version.
			throw new UnsupportedVaultFormatException(Integer.MAX_VALUE, expectedVaultVersion);
		}
	}

	private static class Content {

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

		/**
		 * Performs a very superficial validation of this object.
		 *
		 * @return <code>true</code> if not missing any values
		 */
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
