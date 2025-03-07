package org.cryptomator.cryptolib.v3;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.DirectoryContentCryptor;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.api.RevolvingMasterkey;
import org.cryptomator.cryptolib.v1.CryptorProviderImpl;

import java.security.SecureRandom;

class CryptorImpl implements Cryptor {

	private final RevolvingMasterkey masterkey;
	private final FileContentCryptorImpl fileContentCryptor;
	private final SecureRandom random;

	/**
	 * Package-private constructor.
	 * Use {@link CryptorProviderImpl#provide(Masterkey, SecureRandom)} to obtain a Cryptor instance.
	 */
	CryptorImpl(RevolvingMasterkey masterkey, SecureRandom random) {
		this.masterkey = masterkey;
		this.fileContentCryptor = new FileContentCryptorImpl(random);
		this.random = random;
	}

	@Override
	public FileContentCryptorImpl fileContentCryptor() {
		assertNotDestroyed();
		return fileContentCryptor;
	}

	@Override
	public FileHeaderCryptorImpl fileHeaderCryptor() {
		return fileHeaderCryptor(masterkey.currentRevision());
	}

	@Override
	public FileHeaderCryptorImpl fileHeaderCryptor(int revision) {
		assertNotDestroyed();
		return new FileHeaderCryptorImpl(masterkey, random, revision);
	}

	@Override
	public FileNameCryptorImpl fileNameCryptor() {
		throw new UnsupportedOperationException();
	}

	@Override
	public FileNameCryptorImpl fileNameCryptor(int revision) {
		assertNotDestroyed();
		return new FileNameCryptorImpl(masterkey, revision);
	}

	@Override
	public DirectoryContentCryptorImpl directoryContentCryptor() {
		return new DirectoryContentCryptorImpl(masterkey, random, this);
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
