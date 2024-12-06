/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v3;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.api.RevolvingMasterkey;
import org.cryptomator.cryptolib.v1.CryptorProviderImpl;

import java.security.SecureRandom;

class CryptorImpl implements Cryptor {

	private final RevolvingMasterkey masterkey;
	private final FileContentCryptorImpl fileContentCryptor;
	private final FileHeaderCryptorImpl fileHeaderCryptor;

	/**
	 * Package-private constructor.
	 * Use {@link CryptorProviderImpl#provide(Masterkey, SecureRandom)} to obtain a Cryptor instance.
	 */
	CryptorImpl(RevolvingMasterkey masterkey, SecureRandom random) {
		this.masterkey = masterkey;
		this.fileHeaderCryptor = new FileHeaderCryptorImpl(masterkey, random);
		this.fileContentCryptor = new FileContentCryptorImpl(random);
	}

	@Override
	public FileContentCryptorImpl fileContentCryptor() {
		assertNotDestroyed();
		return fileContentCryptor;
	}

	@Override
	public FileHeaderCryptorImpl fileHeaderCryptor() {
		assertNotDestroyed();
		return fileHeaderCryptor;
	}

	@Override
	public FileNameCryptorImpl fileNameCryptor() {
		throw new UnsupportedOperationException();
	}

	@Override
	public FileNameCryptor fileNameCryptor(int revision) {
		assertNotDestroyed();
		return new FileNameCryptorImpl(masterkey, revision);
	}

	@Override
	public boolean isDestroyed() {
		return masterkey.isDestroyed();
	}

	@Override
	public void close() {
		destroy();
	}

	@Override
	public void destroy() {
		masterkey.destroy();
	}

	private void assertNotDestroyed() {
		if (isDestroyed()) {
			throw new IllegalStateException("Cryptor destroyed.");
		}
	}

}
