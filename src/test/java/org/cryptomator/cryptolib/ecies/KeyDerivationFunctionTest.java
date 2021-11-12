package org.cryptomator.cryptolib.ecies;

import com.google.common.io.BaseEncoding;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.converter.ConvertWith;
import org.junit.jupiter.params.provider.CsvSource;

public class KeyDerivationFunctionTest {

	@DisplayName("ANSI-X9.63-KDF")
	@ParameterizedTest
	@CsvSource(value = {
			"96c05619d56c328ab95fe84b18264b08725b85e33fd34f08, , 16, 443024c3dae66b95e6f5670601558f71",
			"96f600b73ad6ac5629577eced51743dd2c24c21b1ac83ee4, , 16, b6295162a7804f5667ba9070f82fa522",
			"22518b10e70f2a3f243810ae3254139efbee04aa57c7af7d, 75eef81aa3041e33b80971203d2c0c52, 128, c498af77161cc59f2962b9a713e2b215152d139766ce34a776df11866a69bf2e52a13d9c7c6fc878c50c5ea0bc7b00e0da2447cfd874f6cf92f30d0097111485500c90c3af8b487872d04685d14c8d1dc8d7fa08beb0ce0ababc11f0bd496269142d43525a78e5bc79a17f59676a5706dc54d54d4d1f0bd7e386128ec26afc21",
			"7e335afa4b31d772c0635c7b0e06f26fcd781df947d2990a, d65a4812733f8cdbcdfb4b2f4c191d87, 128, c0bd9e38a8f9de14c2acd35b2f3410c6988cf02400543631e0d6a4c1d030365acbf398115e51aaddebdc9590664210f9aa9fed770d4c57edeafa0b8c14f93300865251218c262d63dadc47dfa0e0284826793985137e0a544ec80abf2fdf5ab90bdaea66204012efe34971dc431d625cd9a329b8217cc8fd0d9f02b13f2f6b0b",
	})
	// test vectors from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/800-135testvectors/ansx963_2001.zip
	public void testAnsiX963sha256(@ConvertWith(HexConverter.class) byte[] sharedSecret, @ConvertWith(HexConverter.class) byte[] sharedInfo, int outLen, @ConvertWith(HexConverter.class) byte[] expectedResult) {
		byte[] result = KeyDerivationFunction.ansiX963sha256Kdf(sharedSecret, sharedInfo, outLen);
		Assertions.assertArrayEquals(expectedResult, result);
	}

	@DisplayName("kdf.deriveKey()")
	@Test
	public void testDeriveKey() {
		byte[] secret =  BaseEncoding.base16().lowerCase().decode("96c05619d56c328ab95fe84b18264b08725b85e33fd34f08");

		byte[] result = KeyDerivationFunction.ANSI_X963_SHA256_KDF.deriveKey(secret, 16);

		byte[] expected =  BaseEncoding.base16().lowerCase().decode("443024c3dae66b95e6f5670601558f71");
		Assertions.assertArrayEquals(expected, result);
	}

}