/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib;

import java.nio.charset.StandardCharsets;

import org.hamcrest.CoreMatchers;
import org.junit.Assert;
import org.junit.Test;

public class KeyFileTest {

	@Test
	public void testParse() {
		final String serialized = "{\"version\":3,\"scryptSalt\":\"AAAAAAAAAAA=\",\"scryptCostParam\":2,\"scryptBlockSize\":8," //
				+ "\"primaryMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
				+ "\"hmacMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
				+ "\"versionMac\":\"iUmRRHITuyJsJbVNqGNw+82YQ4A3Rma7j/y1v0DCVLA=\"}";
		KeyFile keyFile = KeyFile.parse(serialized.getBytes());
		Assert.assertEquals(3, keyFile.getVersion().intValue());
	}

	@Test(expected = IllegalArgumentException.class)
	public void testParseInvalid() {
		final String serialized = "{i don't know syntax}";
		KeyFile.parse(serialized.getBytes());
	}

	@Test
	public void testSerialize() {
		KeyFile keyFile = new KeyFile();
		keyFile.setScryptSalt(new byte[8]);
		String serialized = new String(keyFile.serialize(), StandardCharsets.UTF_8);
		Assert.assertThat(serialized, CoreMatchers.containsString("\"scryptSalt\":\"AAAAAAAAAAA=\""));
	}

}
