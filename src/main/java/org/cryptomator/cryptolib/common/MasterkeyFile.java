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
import java.util.Arrays;
import java.util.Optional;

public class MasterkeyFile {

	private static final Gson GSON = new GsonBuilder() //
			.setPrettyPrinting() //
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

	public static byte[] lock(Masterkey masterkey, CharSequence passphrase, byte[] pepper, int vaultVersion) {
		// TODO
		return null;
	}

//
//	public void changePw() {
//		CharSequence oldPw = "";
//		CharSequence newPw = "";
//		try {
//			save(load(oldPw).loadKey("asd"), newPw);
//		} catch (KeyLoadingFailedException e) {
//			e.printStackTrace();
//		} finally {
//
//		}
//	}

	public MasterkeyFileLoader unlock(CharSequence passphrase, byte[] pepper, Optional<Integer> expectedVaultVersion) throws CryptoException {
		boolean success = false;
		SecretKey kek = null;
		SecretKey encKey = null;
		SecretKey macKey = null;
		try {
			// derive keys:
			kek = scrypt(passphrase, pepper);
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

	private SecretKey scrypt(CharSequence passphrase, byte[] pepper) {
		byte[] salt = content.scryptSalt;
		byte[] saltAndPepper = new byte[salt.length + pepper.length];
		System.arraycopy(salt, 0, saltAndPepper, 0, salt.length);
		System.arraycopy(pepper, 0, saltAndPepper, salt.length, pepper.length);
		byte[] kekBytes = Scrypt.scrypt(passphrase, saltAndPepper, content.scryptCostParam, content.scryptBlockSize, Masterkey.KEY_LEN_BYTES);
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
