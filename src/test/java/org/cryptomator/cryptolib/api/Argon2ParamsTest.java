package org.cryptomator.cryptolib.api;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class Argon2ParamsTest {

	@Test
	void testDefault() {
		Assertions.assertEquals(64 * 1024, Argon2Params.DEFAULT.memoryKiB());
		Assertions.assertEquals(3, Argon2Params.DEFAULT.iterations());
		Assertions.assertEquals(4, Argon2Params.DEFAULT.parallelism());
		Assertions.assertEquals(new Argon2Params(65536, 3, 4), Argon2Params.DEFAULT);
		Assertions.assertEquals(new Argon2Params(65536, 3, 4).hashCode(), Argon2Params.DEFAULT.hashCode());
		Assertions.assertNotEquals(new Argon2Params(65536, 2, 4), Argon2Params.DEFAULT);
	}

	@ParameterizedTest(name = "m={0} t={1} p={2}")
	@CsvSource({"8, 1, 1", "2097152, 1000, 256", "32, 1, 4"})
	void testValid(int memoryKiB, int iterations, int parallelism) {
		Argon2Params params = new Argon2Params(memoryKiB, iterations, parallelism);
		Assertions.assertEquals(memoryKiB, params.memoryKiB());
		Assertions.assertEquals(iterations, params.iterations());
		Assertions.assertEquals(parallelism, params.parallelism());
	}

	@ParameterizedTest(name = "m={0} t={1} p={2}")
	@CsvSource({"7, 1, 1", "2097153, 1, 1", "8, 0, 1", "8, 1001, 1", "8, 1, 0", "8, 1, 257", "31, 1, 4", "-1, 1, 1"})
	void testInvalid(int memoryKiB, int iterations, int parallelism) {
		Assertions.assertThrows(IllegalArgumentException.class, () -> new Argon2Params(memoryKiB, iterations, parallelism));
	}

}
