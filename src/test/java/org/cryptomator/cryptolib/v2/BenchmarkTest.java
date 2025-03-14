/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v2;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

@DisplayName("Benchmark V2 (GCM)")
public class BenchmarkTest {

	@Disabled("only on demand")
	@Test
	public void runBenchmarks() throws RunnerException {
		// Taken from http://stackoverflow.com/a/30486197/4014509:
		Options opt = new OptionsBuilder()
				// Specify which benchmarks to run
				.include(getClass().getPackage().getName() + ".*Benchmark.*")
				// Set the following options as needed
				.threads(2).forks(1) //
				.shouldFailOnError(true).shouldDoGC(true)
				// .jvmArgs("-XX:+UnlockDiagnosticVMOptions", "-XX:+PrintInlining")
				// .addProfiler(WinPerfAsmProfiler.class)
				.build();

		new Runner(opt).run();
	}

}
