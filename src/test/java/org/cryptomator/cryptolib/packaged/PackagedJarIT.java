package org.cryptomator.cryptolib.packaged;

import org.cryptomator.cryptolib.api.Argon2Params;
import org.cryptomator.cryptolib.api.Cvf8LockedVault;
import org.cryptomator.cryptolib.api.Cvf8UnlockedVault;
import org.cryptomator.cryptolib.api.CvfMasterkey;
import org.cryptomator.cryptolib.api.LockedVault;
import org.cryptomator.cryptolib.api.UnlockedVault;
import org.cryptomator.cryptolib.api.UvfLockedVault;
import org.cryptomator.cryptolib.api.UvfUnlockedVault;
import org.cryptomator.cryptolib.api.VaultDirectory;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Map;

/**
 * Smoke test of the public API through the packaged jar, run by the failsafe plugin after packaging: the JVM applies the multi-release layer with the sealed {@code LockedVault}/{@code UnlockedVault}
 * only to jars, so sealed-hierarchy mistakes surface here and not in the regular test run. Lives in its own package because the jar is sealed.
 */
class PackagedJarIT {

	private static final SecureRandom CSPRNG = new SecureRandom();

	@Test
	@DisplayName("create, serialize, parse and unlock a CVF8 vault")
	void testCvf8() {
		byte[] config;
		byte[] ciphertext;
		VaultDirectory root;
		try (CvfMasterkey masterkey = CvfMasterkey.generate(CSPRNG); Cvf8UnlockedVault vault = Cvf8UnlockedVault.create(masterkey, 220, CSPRNG)) {
			config = vault.serializeConfig();
			ciphertext = vault.encryptFile("hello".getBytes(StandardCharsets.UTF_8));
			root = vault.rootDirectory();
			LockedVault locked = LockedVault.parse(config);
			Cvf8LockedVault cvf8 = Assertions.assertInstanceOf(Cvf8LockedVault.class, locked);
			try (UnlockedVault unlocked = cvf8.unlock(masterkey, CSPRNG)) {
				Assertions.assertEquals(root, unlocked.rootDirectory());
				Assertions.assertArrayEquals("hello".getBytes(StandardCharsets.UTF_8), unlocked.decryptFile(ciphertext));
			}
		}
	}

	@Test
	@DisplayName("create, serialize, parse and unlock a UVF vault")
	void testUvf() {
		KeyPair recoveryKey = UvfUnlockedVault.generateRecoveryKey(CSPRNG);
		byte[] config;
		byte[] ciphertext;
		String recoveryWords;
		VaultDirectory root;
		try (UvfUnlockedVault vault = UvfUnlockedVault.create(CSPRNG)) {
			vault.setPassword("secret", new Argon2Params(64, 1, 1));
			vault.setRecoveryKey(recoveryKey);
			config = vault.serializeConfig();
			recoveryWords = vault.serializedRecoveryKey();
			ciphertext = vault.encryptFile("hello".getBytes(StandardCharsets.UTF_8));
			root = vault.rootDirectory();
		}
		LockedVault locked = LockedVault.parse(config);
		UvfLockedVault uvf = Assertions.assertInstanceOf(UvfLockedVault.class, locked);
		try (UnlockedVault unlocked = uvf.unlock("secret", CSPRNG)) {
			Assertions.assertEquals(root, unlocked.rootDirectory());
			Assertions.assertArrayEquals("hello".getBytes(StandardCharsets.UTF_8), unlocked.decryptFile(ciphertext));
		}
		try (UnlockedVault recovered = locked.recover(recoveryWords, CSPRNG)) {
			Assertions.assertEquals(root, recovered.rootDirectory());
			Assertions.assertEquals(recoveryWords, recovered.serializedRecoveryKey());
		}
		Map<Integer, byte[]> pins;
		try (UvfUnlockedVault unlocked = uvf.unlock("secret", CSPRNG)) {
			pins = unlocked.seedDigests();
		}
		uvf.requireSeeds(pins.values()).unlock("secret", CSPRNG).close();
	}

}
