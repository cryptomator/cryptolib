package org.cryptomator.cryptolib.common;

import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptolib.api.*;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.security.SecureRandom;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;

public class MasterkeyFileAccessTest {

	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.NULL_RANDOM;
	private static final byte[] DEFAULT_PEPPER = new byte[0];

	private PerpetualMasterkey key = new PerpetualMasterkey(new byte[64]);
	private MasterkeyFile keyFile = new MasterkeyFile();
	private MasterkeyFileAccess masterkeyFileAccess = Mockito.spy(new MasterkeyFileAccess(DEFAULT_PEPPER, RANDOM_MOCK));

	@BeforeEach
	public void setup() {
		keyFile.version = 3;
		keyFile.scryptSalt = new byte[8];
		keyFile.scryptCostParam = 2;
		keyFile.scryptBlockSize = 8;
		keyFile.encMasterKey = BaseEncoding.base64().decode("mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==");
		keyFile.macMasterKey = BaseEncoding.base64().decode("mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==");
		keyFile.versionMac = BaseEncoding.base64().decode("iUmRRHITuyJsJbVNqGNw+82YQ4A3Rma7j/y1v0DCVLA=");
	}

	@Test
	@DisplayName("changePassphrase(MasterkeyFile, ...)")
	public void testChangePassphraseWithMasterkeyFile() throws CryptoException {
		MasterkeyFile changed1 = masterkeyFileAccess.changePassphrase(keyFile, "asd", "qwe");
		MasterkeyFile changed2 = masterkeyFileAccess.changePassphrase(changed1, "qwe", "asd");

		MatcherAssert.assertThat(keyFile.encMasterKey, not(equalTo(changed1.encMasterKey)));
		Assertions.assertArrayEquals(keyFile.encMasterKey, changed2.encMasterKey);
	}

	@Test
	@DisplayName("readAllegedVaultVersion()")
	public void testReadAllegedVaultVersion() throws IOException {
		byte[] content = "{\"version\": 1337}".getBytes(UTF_8);

		int version = MasterkeyFileAccess.readAllegedVaultVersion(content);

		Assertions.assertEquals(1337, version);
	}

	@Nested
	@DisplayName("with serialized keyfile")
	class WithSerializedKeyFile {

		private byte[] serializedKeyFile;

		@BeforeEach
		public void setup() throws IOException {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			masterkeyFileAccess.persist(key, out, "asd", 999, 2);
			serializedKeyFile = out.toByteArray();
		}

		@Test
		@DisplayName("changePassphrase(byte[], ...)")
		public void testChangePassphraseWithRawBytes() throws CryptoException, IOException {
			byte[] changed = masterkeyFileAccess.changePassphrase(serializedKeyFile, "asd", "qwe");
			byte[] restored = masterkeyFileAccess.changePassphrase(changed, "qwe", "asd");

			MatcherAssert.assertThat(changed, not(equalTo(serializedKeyFile)));
			Assertions.assertArrayEquals(serializedKeyFile, restored);
		}

		@Test
		@DisplayName("load()")
		public void testLoad() throws IOException {
			InputStream in = new ByteArrayInputStream(serializedKeyFile);

			PerpetualMasterkey loaded = masterkeyFileAccess.load(in, "asd");

			Assertions.assertArrayEquals(key.getEncoded(), loaded.getEncoded());
		}

		@Test
		@DisplayName("load() unrelated json file")
		public void testLoadInvalid() {
			String content = "{\"foo\": 42}";
			InputStream in = new ByteArrayInputStream(content.getBytes(UTF_8));

			Assertions.assertThrows(IOException.class, () -> {
				masterkeyFileAccess.load(in, "asd");
			});
		}

		@Test
		@DisplayName("load() non-json file")
		public void testLoadMalformed() {
			final String content = "not even json";
			InputStream in = new ByteArrayInputStream(content.getBytes(UTF_8));

			Assertions.assertThrows(IOException.class, () -> {
				masterkeyFileAccess.load(in, "asd");
			});
		}

	}

	@Nested
	@DisplayName("unlock()")
	class Unlock {

		@Test
		@DisplayName("with correct password")
		public void testUnlockWithCorrectPassword() throws CryptoException {
			Masterkey key = masterkeyFileAccess.unlock(keyFile, "asd");

			Assertions.assertNotNull(key);
		}

		@Test
		@DisplayName("with invalid password")
		public void testUnlockWithIncorrectPassword() {
			Assertions.assertThrows(InvalidPassphraseException.class, () -> {
				masterkeyFileAccess.unlock(keyFile, "qwe");
			});
		}

		@Test
		@DisplayName("with correct password but invalid pepper")
		public void testUnlockWithIncorrectPepper() {
			MasterkeyFileAccess masterkeyFileAccess = new MasterkeyFileAccess(new byte[1], RANDOM_MOCK);

			Assertions.assertThrows(InvalidPassphraseException.class, () -> {
				masterkeyFileAccess.unlock(keyFile, "qwe");
			});
		}

	}

	@Nested
	@DisplayName("lock()")
	class Lock {

		@Test
		@DisplayName("creates expected values")
		public void testLock() {
			MasterkeyFile keyFile = masterkeyFileAccess.lock(key, "asd", 3, 2);

			Assertions.assertEquals(3, keyFile.version);
			Assertions.assertArrayEquals(new byte[8], keyFile.scryptSalt);
			Assertions.assertEquals(2, keyFile.scryptCostParam);
			Assertions.assertEquals(8, keyFile.scryptBlockSize);
			Assertions.assertArrayEquals(BaseEncoding.base64().decode("mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q=="), keyFile.encMasterKey);
			Assertions.assertArrayEquals(BaseEncoding.base64().decode("mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q=="), keyFile.macMasterKey);
			Assertions.assertArrayEquals(BaseEncoding.base64().decode("iUmRRHITuyJsJbVNqGNw+82YQ4A3Rma7j/y1v0DCVLA="), keyFile.versionMac);
		}

		@Test
		@DisplayName("different passwords -> different wrapped keys")
		public void testLockWithDifferentPasswords() {
			MasterkeyFile keyFile1 = masterkeyFileAccess.lock(key, "asd", 8, 2);
			MasterkeyFile keyFile2 = masterkeyFileAccess.lock(key, "qwe", 8, 2);

			MatcherAssert.assertThat(keyFile1.encMasterKey, not(equalTo(keyFile2.encMasterKey)));
		}

		@Test
		@DisplayName("different peppers -> different wrapped keys")
		public void testLockWithDifferentPeppers() {
			byte[] pepper1 = new byte[]{(byte) 0x01};
			byte[] pepper2 = new byte[]{(byte) 0x02};
			MasterkeyFileAccess masterkeyFileAccess1 = new MasterkeyFileAccess(pepper1, RANDOM_MOCK);
			MasterkeyFileAccess masterkeyFileAccess2 = new MasterkeyFileAccess(pepper2, RANDOM_MOCK);

			MasterkeyFile keyFile1 = masterkeyFileAccess1.lock(key, "asd", 8, 2);
			MasterkeyFile keyFile2 = masterkeyFileAccess2.lock(key, "asd", 8, 2);

			MatcherAssert.assertThat(keyFile1.encMasterKey, not(equalTo(keyFile2.encMasterKey)));
		}

	}

	@Test
	@DisplayName("persist and load")
	public void testPersistAndLoad(@TempDir Path tmpDir) throws IOException, MasterkeyLoadingFailedException {
		Path masterkeyFile = tmpDir.resolve("masterkey.cryptomator");

		masterkeyFileAccess.persist(key, masterkeyFile, "asd");
		PerpetualMasterkey loaded = masterkeyFileAccess.load(masterkeyFile, "asd");

		Assertions.assertArrayEquals(key.getEncoded(), loaded.getEncoded());
	}

}