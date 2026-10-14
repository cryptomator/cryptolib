package org.cryptomator.cryptolib.api;

/**
 * Cost parameters of Argon2id, which derives the key encryption key of a password-protected UVF vault, see {@link UvfUnlockedVault#setPassword(CharSequence, Argon2Params)}.
 */
public final class Argon2Params {

	/** Upper bound accepted when reading parameters from a vault, protecting against resource exhaustion by malicious files. */
	public static final int MAX_MEMORY_KIB = 2 * 1024 * 1024;
	/** Upper bound accepted when reading parameters from a vault, protecting against resource exhaustion by malicious files. */
	public static final int MAX_ITERATIONS = 1000;
	/** Upper bound accepted when reading parameters from a vault, protecting against resource exhaustion by malicious files. */
	public static final int MAX_PARALLELISM = 256;

	/** The second recommended option of RFC 9106 section 4: 64 MiB of memory, 3 passes, 4 lanes. */
	public static final Argon2Params DEFAULT = new Argon2Params(64 * 1024, 3, 4);

	private final int memoryKiB;
	private final int iterations;
	private final int parallelism;

	/**
	 * @param memoryKiB Memory size in KiB; at least {@code 8 * parallelism}, at most {@link #MAX_MEMORY_KIB}
	 * @param iterations Number of passes; at least 1, at most {@link #MAX_ITERATIONS}
	 * @param parallelism Degree of parallelism (lanes); at least 1, at most {@link #MAX_PARALLELISM}
	 */
	public Argon2Params(int memoryKiB, int iterations, int parallelism) {
		if (parallelism < 1 || parallelism > MAX_PARALLELISM) {
			throw new IllegalArgumentException("parallelism must be within [1, " + MAX_PARALLELISM + "]");
		}
		if (memoryKiB < 8 * parallelism || memoryKiB > MAX_MEMORY_KIB) {
			throw new IllegalArgumentException("memoryKiB must be within [" + 8 * parallelism + ", " + MAX_MEMORY_KIB + "]");
		}
		if (iterations < 1 || iterations > MAX_ITERATIONS) {
			throw new IllegalArgumentException("iterations must be within [1, " + MAX_ITERATIONS + "]");
		}
		this.memoryKiB = memoryKiB;
		this.iterations = iterations;
		this.parallelism = parallelism;
	}

	public int memoryKiB() {
		return memoryKiB;
	}

	public int iterations() {
		return iterations;
	}

	public int parallelism() {
		return parallelism;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		} else if (obj instanceof Argon2Params) {
			Argon2Params other = (Argon2Params) obj;
			return memoryKiB == other.memoryKiB && iterations == other.iterations && parallelism == other.parallelism;
		} else {
			return false;
		}
	}

	@Override
	public int hashCode() {
		return 31 * (31 * memoryKiB + iterations) + parallelism;
	}

	@Override
	public String toString() {
		return "Argon2Params[memoryKiB=" + memoryKiB + ", iterations=" + iterations + ", parallelism=" + parallelism + "]";
	}

}
