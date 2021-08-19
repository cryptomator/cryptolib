package org.cryptomator.cryptolib.ecies;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import javax.crypto.AEADBadTagException;
import javax.crypto.KeyAgreement;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

public class ECIntegratedEncryptionSchemeTest {

	@Nested
	@DisplayName("With null encryption scheme...")
	public class WithIdentityCipher {

		private AuthenticatedEncryption ae;
		private KeyDerivationFunction kdf;
		private ECIntegratedEncryptionScheme ecies;
		private KeyPair ephemeral;
		private KeyPair receiver;
		private byte[] expectedSharedSecret;
		private byte[] derivedSecret;

		@BeforeEach
		public void setup() throws AEADBadTagException, NoSuchAlgorithmException, InvalidKeyException {
			this.ephemeral = KeyPairGenerator.getInstance("EC").generateKeyPair();
			this.receiver = KeyPairGenerator.getInstance("EC").generateKeyPair();
			KeyAgreement ecdh = KeyAgreement.getInstance("ECDH");
			ecdh.init(ephemeral.getPrivate());
			ecdh.doPhase(receiver.getPublic(), true);
			this.expectedSharedSecret = ecdh.generateSecret();
			this.ae = Mockito.mock(AuthenticatedEncryption.class);
			this.kdf = Mockito.mock(KeyDerivationFunction.class);
			this.ecies = new ECIntegratedEncryptionScheme(ae, kdf);
			this.derivedSecret = new byte[32];
			Arrays.fill(derivedSecret, (byte) 0xAA);

			// set up null encryption
			Mockito.doReturn(32).when(ae).requiredSecretBytes();
			Mockito.doAnswer(invocation -> invocation.getArgument(1)).when(ae).encrypt(Mockito.any(), Mockito.any());
			Mockito.doAnswer(invocation -> invocation.getArgument(1)).when(ae).decrypt(Mockito.any(), Mockito.any());

			// set up null KDF
			Mockito.doReturn(derivedSecret).when(kdf).deriveKey(expectedSharedSecret, 32);
		}

		@Test
		public void testEncryptWithInvalidKey() {
			ECPrivateKey invalidSk = Mockito.mock(ECPrivateKey.class);
			ECPublicKey validPk = (ECPublicKey) receiver.getPublic();
			Mockito.doReturn("WRONG").when(invalidSk).getAlgorithm();

			Assertions.assertThrows(IllegalArgumentException.class, () -> {
				ecies.encrypt(invalidSk, validPk, new byte[42]);
			});
		}

		@Test
		public void testEncrypt() {
			byte[] cleartext = "secret message".getBytes(StandardCharsets.UTF_8);

			byte[] ciphertext = ecies.encrypt((ECPrivateKey) ephemeral.getPrivate(), (ECPublicKey) receiver.getPublic(), cleartext);

			Assertions.assertArrayEquals(cleartext, ciphertext);
			Mockito.verify(kdf).deriveKey(Mockito.any(), Mockito.eq(32));
			Mockito.verify(ae).encrypt(derivedSecret, cleartext);
		}

		@Test
		public void testDecrypt() throws AEADBadTagException {
			byte[] ciphertext = "secret message".getBytes(StandardCharsets.UTF_8);

			byte[] cleartext = ecies.decrypt((ECPrivateKey) receiver.getPrivate(), (ECPublicKey) ephemeral.getPublic(), ciphertext);

			Assertions.assertArrayEquals(ciphertext, cleartext);
			Mockito.verify(kdf).deriveKey(Mockito.any(), Mockito.eq(32));
			Mockito.verify(ae).decrypt(derivedSecret, cleartext);
		}

	}

	@Nested
	@DisplayName("With Cryptomator Hub encryption scheme...")
	public class WithHubScheme {

		private ECIntegratedEncryptionScheme ecies = ECIntegratedEncryptionScheme.HUB;
		private KeyPairGenerator keyGen;
		private KeyPair receiverKeyPair;

		@BeforeEach
		public void setup() throws NoSuchAlgorithmException {
			this.keyGen = KeyPairGenerator.getInstance("EC");
			this.receiverKeyPair = keyGen.generateKeyPair();
		}

		@Test
		@DisplayName("encrypt(...)")
		public void testEncrypt() {
			byte[] cleartext = "hello world".getBytes(StandardCharsets.UTF_8);
			EncryptedMessage msg = ecies.encrypt(keyGen, (ECPublicKey) receiverKeyPair.getPublic(), cleartext);
			Assertions.assertNotNull(msg.getCiphertext());
			Assertions.assertNotNull(msg.getEphPublicKey());
		}

		@Test
		@DisplayName("encrypt(...) with invalid keygen")
		public void testEncryptWithInvalidKeyGen() throws NoSuchAlgorithmException {
			KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance("RSA");
			byte[] cleartext = "hello world".getBytes(StandardCharsets.UTF_8);
			ECPublicKey receiverPublicKey = (ECPublicKey) receiverKeyPair.getPublic();

			Assertions.assertThrows(IllegalArgumentException.class, () -> {
				ecies.encrypt(rsaKeyGen, receiverPublicKey, cleartext);
			});
		}

		@Nested
		@DisplayName("With Cryptomator Hub encryption scheme...")
		public class WithEncryptedMessage {

			private byte[] expectedCleartext = "hello world".getBytes(StandardCharsets.UTF_8);
			private EncryptedMessage encryptedMessage;

			@BeforeEach
			public void setup() throws NoSuchAlgorithmException {
				byte[] cleartext = "hello world".getBytes(StandardCharsets.UTF_8);
				this.encryptedMessage = ecies.encrypt(keyGen, (ECPublicKey) receiverKeyPair.getPublic(), cleartext);
			}

			@Test
			@DisplayName("decrypt(...)")
			public void testDecrypt() throws AEADBadTagException {
				byte[] cleartext = ecies.decrypt((ECPrivateKey) receiverKeyPair.getPrivate(), encryptedMessage);
				Assertions.assertArrayEquals(expectedCleartext, cleartext);
			}

			@Test
			@DisplayName("decrypt(...) with invalid key")
			public void testDecryptWithInvalidKey() {
				ECPrivateKey wrongPrivateKey = (ECPrivateKey) keyGen.generateKeyPair().getPrivate();
				Assertions.assertThrows(AEADBadTagException.class, () -> {
					ecies.decrypt(wrongPrivateKey, encryptedMessage);
				});
			}

		}

	}

}