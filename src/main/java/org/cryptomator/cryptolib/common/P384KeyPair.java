package org.cryptomator.cryptolib.common;

import org.jetbrains.annotations.Contract;

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

	@Contract(value = "-> new", pure = true)
	public static P384KeyPair generate() {
		KeyPair keyPair = getKeyPairGenerator().generateKeyPair();
		return new P384KeyPair(keyPair);
	}

	/**
	 * Loads a key pair from the given file
	 *
	 * @param p12File    A .p12 file
	 * @param passphrase The password to protect the key material
	 * @return loaded key pair
	 * @throws IOException             In case of I/O errors
	 * @throws Pkcs12PasswordException If the supplied password is incorrect
	 * @throws Pkcs12Exception         If any cryptographic operation fails
	 */
	public static P384KeyPair load(Path p12File, char[] passphrase) throws IOException, Pkcs12PasswordException, Pkcs12Exception {
		try (InputStream in = Files.newInputStream(p12File, StandardOpenOption.READ)) {
			return load(in, passphrase);
		}
	}

	/**
	 * Loads a key pair from the given input stream
	 *
	 * @param in         An input stream providing PKCS#12 formatted data
	 * @param passphrase The password to protect the key material
	 * @return loaded key pair
	 * @throws IOException             In case of I/O errors
	 * @throws Pkcs12PasswordException If the supplied password is incorrect
	 * @throws Pkcs12Exception         If any cryptographic operation fails
	 */
	public static P384KeyPair load(InputStream in, char[] passphrase) throws IOException, Pkcs12PasswordException, Pkcs12Exception {
		KeyPair keyPair = Pkcs12Helper.importFrom(in, passphrase);
		return new P384KeyPair(keyPair);
	}

	/**
	 * Stores this key pair in PKCS#12 format at the given path
	 *
	 * @param p12File    The path of the .p12 file
	 * @param passphrase The password to protect the key material
	 * @throws IOException     In case of I/O errors
	 * @throws Pkcs12Exception If any cryptographic operation fails
	 */
	public void store(Path p12File, char[] passphrase) throws IOException, Pkcs12Exception {
		Path tmpFile = p12File.resolveSibling(p12File.getFileName().toString() + ".tmp");
		try (OutputStream out = Files.newOutputStream(tmpFile, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
			store(out, passphrase);
		}
		Files.move(tmpFile, p12File, StandardCopyOption.REPLACE_EXISTING);
	}

	/**
	 * Stores this key in PKCS#12 format to the given output stream
	 *
	 * @param out        The output stream to which the data will be written
	 * @param passphrase The password to protect the key material
	 * @throws IOException     In case of I/O errors
	 * @throws Pkcs12Exception If any cryptographic operation fails
	 */
	public void store(OutputStream out, char[] passphrase) throws IOException, Pkcs12Exception {
		Pkcs12Helper.exportTo(keyPair(), out, passphrase, SIGNATURE_ALG);
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
