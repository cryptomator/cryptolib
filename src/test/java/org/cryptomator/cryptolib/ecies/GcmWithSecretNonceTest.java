package org.cryptomator.cryptolib.ecies;

import org.cryptomator.cryptolib.common.CipherSupplier;
import org.cryptomator.cryptolib.common.GcmTestHelper;
import org.cryptomator.cryptolib.common.ObjectPool;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.converter.ConvertWith;
import org.junit.jupiter.params.provider.CsvSource;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Test vectors from https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
 */
public class GcmWithSecretNonceTest {

	private final GcmWithSecretNonce ae = new GcmWithSecretNonce();

	@BeforeEach
	public void setup() {
		// reset cipher state to avoid InvalidAlgorithmParameterExceptions due to IV-reuse
		GcmTestHelper.reset((mode, key, params) -> {
			try (ObjectPool.Lease<Cipher> cipher = CipherSupplier.AES_GCM.encrypt(key, params)) {
				cipher.get();
			}
		});
	}

	@Test
	public void testRequiredSecretBytes() {
		Assertions.assertEquals(44, ae.requiredSecretBytes());
	}

	@ParameterizedTest
	@CsvSource(value = {
			"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000, , 530f8afbc74536b9a963b4f1c4cb738b", // test case 13
			"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000, 00000000000000000000000000000000, cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919", // test case 14
			"feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308cafebabefacedbaddecaf888, d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255, 522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015adb094dac5d93471bdec1a502270e3cc6c", // test case 15
	})
	public void testEncrypt(@ConvertWith(HexConverter.class) byte[] secret, @ConvertWith(HexConverter.class) byte[] plaintext, @ConvertWith(HexConverter.class) byte[] expectedCiphertext) {
		byte[] ciphertext = ae.encrypt(secret, plaintext);
		Assertions.assertArrayEquals(expectedCiphertext, ciphertext);
	}

	@ParameterizedTest
	@CsvSource(value = {
			"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000, , 530f8afbc74536b9a963b4f1c4cb738b", // test case 13
			"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000, 00000000000000000000000000000000, cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919", // test case 14
			"feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308cafebabefacedbaddecaf888, d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255, 522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015adb094dac5d93471bdec1a502270e3cc6c", // test case 15
	})
	public void testDecrypt(@ConvertWith(HexConverter.class) byte[] secret, @ConvertWith(HexConverter.class) byte[] expectedPlaintext, @ConvertWith(HexConverter.class) byte[] ciphertext) throws AEADBadTagException {
		byte[] plaintext = ae.decrypt(secret, ciphertext);
		Assertions.assertArrayEquals(expectedPlaintext, plaintext);
	}


	@ParameterizedTest
	@CsvSource(value = {
			"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000001, 530f8afbc74536b9a963b4f1c4cb738b",
			"0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000, 530f8afbc74536b9a963b4f1c4cb738b",
	})
	public void testDecryptInvalid(@ConvertWith(HexConverter.class) byte[] secret, @ConvertWith(HexConverter.class) byte[] ciphertext) {
		Assertions.assertThrows(AEADBadTagException.class, () -> {
			ae.decrypt(secret, ciphertext);
		});
	}

}