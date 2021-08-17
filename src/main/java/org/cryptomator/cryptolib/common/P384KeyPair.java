package org.cryptomator.cryptolib.common;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;

public class P384KeyPair extends ECKeyPair {

	private static final String EC_ALG = "EC";
	private static final String EC_CURVE_NAME = "secp384r1";
	private static final String SIGNATURE_ALG = "SHA384withECDSA";

	private P384KeyPair(KeyPair keyPair) {
		super(keyPair);
	}

	public static P384KeyPair generate() {
		KeyPair keyPair = getKeyPairGenerator().generateKeyPair();
		return new P384KeyPair(keyPair);
	}

	/**
	 * Loads a key pair from the given file
	 *
	 * @param p12File    A PKCS12 file
	 * @param passphrase The password to protect the key material
	 * @return
	 * @throws IOException             In case of I/O errors
	 * @throws Pkcs12PasswordException If the supplied password is incorrect
	 * @throws Pkcs12Exception         If any cryptographic operation fails
	 */
	public static P384KeyPair load(Path p12File, char[] passphrase) throws IOException, Pkcs12PasswordException, Pkcs12Exception {
		try (InputStream in = Files.newInputStream(p12File, StandardOpenOption.READ)) {
			KeyPair keyPair = Pkcs12Helper.load(in, passphrase);
			return new P384KeyPair(keyPair);
		}
	}

	/**
	 * in PKCS#12 format at the given path.
	 *
	 * @param p12File    The path of the .p12 file
	 * @param passphrase The password to protect the key material
	 * @throws IOException     In case of I/O errors
	 * @throws Pkcs12Exception If any cryptographic operation fails
	 */
	public void store(Path p12File, char[] passphrase) throws IOException, Pkcs12Exception {
		Path tmpFile = p12File.resolveSibling(p12File.getFileName().toString() + ".tmp");
		try (OutputStream out = Files.newOutputStream(tmpFile, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
			Pkcs12Helper.export(this.keyPair(), out, passphrase, SIGNATURE_ALG);
		}
		Files.move(tmpFile, p12File, StandardCopyOption.REPLACE_EXISTING);
	}

	private static KeyPairGenerator getKeyPairGenerator() {
		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance(EC_ALG);
			keyGen.initialize(new ECGenParameterSpec(EC_CURVE_NAME));
			return keyGen;
		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
			throw new IllegalStateException(EC_CURVE_NAME + " curve not supported");
		}
	}

}
