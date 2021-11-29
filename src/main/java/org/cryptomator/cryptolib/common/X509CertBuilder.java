package org.cryptomator.cryptolib.common;

import com.google.common.base.Preconditions;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

/**
 * Helper class to create self-signed X509v3 certificates from {@link KeyPair key pairs}.
 */
public class X509CertBuilder {

	private static final ASN1ObjectIdentifier ASN1_SUBJECT_KEY_ID = new ASN1ObjectIdentifier("2.5.29.14");

	private final KeyPair keyPair;
	private final ContentSigner signer;
	private X500Name issuer;
	private X500Name subject;
	private Date notBefore;
	private Date notAfter;

	private X509CertBuilder(KeyPair keyPair, ContentSigner signer) {
		this.keyPair = keyPair;
		this.signer = signer;
	}

	/**
	 * @param keyPair      A key pair
	 * @param signatureAlg A signature algorithm suited for the given key pair
	 * @return A new X509 certificate builder
	 * @see <a href="https://docs.oracle.com/en/java/javase/16/docs/specs/security/standard-names.html#signature-algorithms">available algorithms</a>
	 */
	static X509CertBuilder init(KeyPair keyPair, String signatureAlg) {
		try {
			ContentSigner signer = new JcaContentSignerBuilder(signatureAlg).build(keyPair.getPrivate());
			return new X509CertBuilder(keyPair, signer);
		} catch (OperatorCreationException e) {
			throw new IllegalArgumentException("Invalid signature algorithm / key combination", e);
		}
	}

	/**
	 * Sets the certificate's issuer
	 *
	 * @param issuer DistinguishedName as defined in RFC 4514, e.g. <code>CN=Issuer</code>
	 * @return <code>this</code>
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4514#section-4">RFC 4514, Examples</a>
	 */
	public X509CertBuilder withIssuer(String issuer) {
		this.issuer = new X500Name(issuer);
		return this;
	}

	/**
	 * Sets the certificate's subject
	 *
	 * @param subject DistinguishedName as defined in RFC 4514, e.g. <code>CN=Subject</code>
	 * @return <code>this</code>
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4514#section-4">RFC 4514, Examples</a>
	 */
	public X509CertBuilder withSubject(String subject) {
		this.subject = new X500Name(subject);
		return this;
	}

	/**
	 * Sets the certificate's begin of validity period
	 *
	 * @param notBefore date before which the certificate is not valid.
	 * @return <code>this</code>
	 */
	public X509CertBuilder withNotBefore(Instant notBefore) {
		this.notBefore = Date.from(notBefore);
		return this;
	}

	/**
	 * Sets the certificate's end of validity period
	 *
	 * @param notAfter date after which the certificate is not valid.
	 * @return <code>this</code>
	 */
	public X509CertBuilder withNotAfter(Instant notAfter) {
		this.notAfter = Date.from(notAfter);
		return this;
	}

	private void validate() throws IllegalStateException {
		Preconditions.checkState(issuer != null, "issuer not set");
		Preconditions.checkState(subject != null, "subject not set");
		Preconditions.checkState(notBefore != null, "notBefore not set");
		Preconditions.checkState(notAfter != null, "notAfter not set");
		Preconditions.checkState(notBefore.compareTo(notAfter) < 0, "notBefore must be before notAfter");
	}

	/**
	 * Creates a self-signed X509Certificate containing the public key and signed with the private key of a given key pair.
	 *
	 * @return A self-signed X509Certificate
	 * @throws CertificateException  If certificate generation failed, e.g. due to invalid parameters
	 * @throws IllegalStateException If one or more required parameters have not been set yet
	 */
	public X509Certificate build() throws CertificateException, IllegalStateException {
		validate();
		try (InputStream in = new ByteArrayInputStream(buildCertHolder().getEncoded())) {
			return (X509Certificate) getCertFactory().generateCertificate(in);
		} catch (IOException e) {
			throw new CertificateException(e);
		}
	}

	private X509CertificateHolder buildCertHolder() throws CertIOException {
		X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder( //
				issuer, //
				randomSerialNo(), //
				notBefore, //
				notAfter, //
				subject, //
				keyPair.getPublic());
		certificateBuilder.addExtension(ASN1_SUBJECT_KEY_ID, false, getX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.getPublic()));
		return certificateBuilder.build(signer);
	}

	private static BigInteger randomSerialNo() {
		return BigInteger.valueOf(UUID.randomUUID().getMostSignificantBits());
	}

	private static JcaX509ExtensionUtils getX509ExtensionUtils() {
		try {
			return new JcaX509ExtensionUtils();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("Every implementation of the Java platform is required to support SHA-1.");
		}
	}

	private static CertificateFactory getCertFactory() {
		try {
			return CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			throw new IllegalStateException("Every implementation of the Java platform is required to support X.509.");
		}
	}

}