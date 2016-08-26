package org.cryptomator.cryptolib.common;

import java.security.MessageDigest;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class MessageDigestSupplierTest {

	@Rule
	public final ExpectedException thrown = ExpectedException.none();

	@Test
	public void testConstructorWithInvalidDigest() {
		thrown.expect(IllegalArgumentException.class);
		new MessageDigestSupplier("FOO3000").get();
	}

	@Test
	public void testGetSha1() {
		MessageDigest digest1 = MessageDigestSupplier.SHA1.get();
		Assert.assertNotNull(digest1);

		MessageDigest digest2 = MessageDigestSupplier.SHA1.get();
		Assert.assertSame(digest1, digest2);
	}

}
