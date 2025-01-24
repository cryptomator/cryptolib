package org.cryptomator.cryptolib.v3;

import org.cryptomator.cryptolib.api.*;
import org.cryptomator.cryptolib.common.ReseedingSecureRandom;

import java.security.SecureRandom;

public class CryptorProviderImpl implements CryptorProvider {

	@Override
	public Scheme scheme() {
		return Scheme.UVF_DRAFT;
	}

	@Override
	public Cryptor provide(Masterkey masterkey, SecureRandom random) {
		if (masterkey instanceof RevolvingMasterkey) {
			RevolvingMasterkey revolvingMasterkey = (RevolvingMasterkey) masterkey;
			return new CryptorImpl(revolvingMasterkey, ReseedingSecureRandom.create(random));
		} else {
			throw new IllegalArgumentException("V3 Cryptor requires a RevolvingMasterkey.");
		}
	}

}
