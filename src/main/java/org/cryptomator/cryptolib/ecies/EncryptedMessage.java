package org.cryptomator.cryptolib.ecies;

import java.security.interfaces.ECPublicKey;

public class EncryptedMessage {

	private final ECPublicKey ephPublicKey;
	private final byte[] ciphertext;

	public EncryptedMessage(ECPublicKey ephPublicKey, byte[] ciphertext) {
		this.ephPublicKey = ephPublicKey;
		this.ciphertext = ciphertext;
	}

	public ECPublicKey getEphPublicKey() {
		return ephPublicKey;
	}

	public byte[] getCiphertext() {
		return ciphertext;
	}

}
