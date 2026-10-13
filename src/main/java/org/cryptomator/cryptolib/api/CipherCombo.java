package org.cryptomator.cryptolib.api;

/**
 * The combination of ciphers used by a Cryptomator Vault Format 8 vault for file names and file contents.
 */
public enum CipherCombo {
	/**
	 * AES-SIV for file names, AES-CTR + HMAC-SHA256 for file contents.
	 */
	SIV_CTRMAC,

	/**
	 * AES-SIV for file names, AES-GCM for file contents.
	 */
	SIV_GCM
}
