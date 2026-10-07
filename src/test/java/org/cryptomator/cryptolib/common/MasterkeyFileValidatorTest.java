package org.cryptomator.cryptolib.common;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.io.IOException;

public class MasterkeyFileValidatorTest {

	@Nested
	@DisplayName("DEFAULT")
	class Default {

		private MasterkeyFile masterkeyFile;

		@BeforeEach
		public void setup() {
			masterkeyFile = new MasterkeyFile();
			masterkeyFile.version = 999;
			masterkeyFile.scryptSalt = new byte[8];
			masterkeyFile.encMasterKey = new byte[40];
			masterkeyFile.macMasterKey = new byte[40];
			masterkeyFile.versionMac = new byte[32];
		}

		@ParameterizedTest(name = "scryptCostParam = {0}, scryptBlockSize = {1}")
		@DisplayName("accepts scrypt parameters within the upper bounds")
		@CsvSource({ //
				"32768, 8", // default parameters, 32 MiB
				"1048576, 8", // scryptCostParam at DEFAULT_MAX_SCRYPT_COST_PARAM, 1 GiB
				"2, 64", // scryptBlockSize at DEFAULT_MAX_SCRYPT_BLOCK_SIZE
				"524288, 16", // 2^19 * 16 * 128 = 1 GiB, exactly at the memory limit
		})
		public void testAccepts(int scryptCostParam, int scryptBlockSize) {
			masterkeyFile.scryptCostParam = scryptCostParam;
			masterkeyFile.scryptBlockSize = scryptBlockSize;

			Assertions.assertDoesNotThrow(() -> MasterkeyFileValidator.DEFAULT.validate(masterkeyFile));
		}

		@ParameterizedTest(name = "scryptCostParam = {0}, scryptBlockSize = {1}")
		@DisplayName("rejects scrypt parameters exceeding the upper bounds")
		@CsvSource({ //
				"1048577, 1", // scryptCostParam > DEFAULT_MAX_SCRYPT_COST_PARAM
				"2147483647, 1", // scryptCostParam > DEFAULT_MAX_SCRYPT_COST_PARAM
				"2, 65", // scryptBlockSize > DEFAULT_MAX_SCRYPT_BLOCK_SIZE
				"2, 2147483647", // scryptBlockSize > DEFAULT_MAX_SCRYPT_BLOCK_SIZE
				"1048576, 16", // 2^20 * 16 * 128 = 2 GiB, while both factors are within their individual bounds
				"1048576, 64", // both at their upper bounds, 2^20 * 64 * 128 = 8 GiB
		})
		public void testRejects(int scryptCostParam, int scryptBlockSize) {
			masterkeyFile.scryptCostParam = scryptCostParam;
			masterkeyFile.scryptBlockSize = scryptBlockSize;

			Assertions.assertThrows(IOException.class, () -> MasterkeyFileValidator.DEFAULT.validate(masterkeyFile));
		}

	}

}
