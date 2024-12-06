package org.cryptomator.cryptolib.v1;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.api.PerpetualMasterkey;

import java.security.SecureRandom;

class CryptorImpl implements Cryptor {

	private final PerpetualMasterkey masterkey;
	private final FileContentCryptorImpl fileContentCryptor;
	private final FileHeaderCryptorImpl fileHeaderCryptor;
	private final FileNameCryptorImpl fileNameCryptor;

	/**
	 * Package-private constructor.
	 * Use {@link CryptorProviderImpl#provide(Masterkey, SecureRandom)} to obtain a Cryptor instance.
	 */
	CryptorImpl(PerpetualMasterkey masterkey, SecureRandom random) {
		this.masterkey = masterkey;
		this.fileHeaderCryptor = new FileHeaderCryptorImpl(masterkey, random);
		this.fileContentCryptor = new FileContentCryptorImpl(masterkey, random);
		this.fileNameCryptor = new FileNameCryptorImpl(masterkey);
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
		assertNotDestroyed();
		return fileNameCryptor;
	}

	@Override
	public FileNameCryptor fileNameCryptor(int revision) {
		throw new UnsupportedOperationException();
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
