package org.cryptomator.cryptolib.uvf;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import org.cryptomator.cryptolib.api.Argon2Params;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.UvfLockedVault;
import org.cryptomator.cryptolib.api.UvfUnlockedVault;
import org.cryptomator.cryptolib.api.VaultDirectory;
import org.cryptomator.cryptolib.common.ReseedingSecureRandom;
import org.cryptomator.cryptolib.internal.AbstractUnlockedVault;
import org.cryptomator.cryptolib.internal.FileHeaderParts;
import org.cryptomator.cryptolib.internal.RecoveryKeys;
import org.cryptomator.cryptolib.internal.VaultFileImpl;
import org.jspecify.annotations.Nullable;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.text.Normalizer;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

/**
 * An unlocked Unified Vault Format vault.
 */
public final class UvfVault extends AbstractUnlockedVault implements UvfUnlockedVault {

	private final UvfSeeds seeds;
	private final JWEHeader protectedHeader;
	private final SecureRandom csprng;
	private final SecureRandom random;
	private final UvfContentCodec codec;
	private final UvfNames names;
	private @Nullable OctetSequenceKey keyEncryptionKey; // password-derived or member key, null after recovery until set
	private Map<String, Object> keyEncryptionKeyParams; // Argon2 parameters of a password-derived key, else empty
	private @Nullable ECKey recoveryKey; // public key, plus the private part if set as key pair or recovered with it

	UvfVault(UvfSeeds seeds, JWEHeader protectedHeader, @Nullable OctetSequenceKey keyEncryptionKey, Map<String, Object> keyEncryptionKeyParams, @Nullable ECKey recoveryKey, SecureRandom csprng) {
		this(seeds, protectedHeader, keyEncryptionKey, keyEncryptionKeyParams, recoveryKey, csprng, ReseedingSecureRandom.create(csprng));
	}

	// visible for testing
	UvfVault(UvfSeeds seeds, JWEHeader protectedHeader, @Nullable OctetSequenceKey keyEncryptionKey, Map<String, Object> keyEncryptionKeyParams, @Nullable ECKey recoveryKey, SecureRandom csprng, SecureRandom random) {
		super(UvfContentCodec.LAYOUT);
		this.seeds = seeds;
		this.protectedHeader = protectedHeader;
		this.keyEncryptionKey = keyEncryptionKey;
		this.keyEncryptionKeyParams = keyEncryptionKeyParams;
		this.recoveryKey = recoveryKey;
		this.csprng = csprng;
		this.random = random;
		this.codec = new UvfContentCodec(seeds, random);
		this.names = new UvfNames(seeds);
	}

	/**
	 * Creates a new vault, see {@link UvfUnlockedVault#create(SecureRandom)}.
	 *
	 * @param csprng A cryptographically secure random number generator
	 * @return The new, unlocked vault without recipients
	 */
	public static UvfVault create(SecureRandom csprng) {
		return new UvfVault(UvfSeeds.create(csprng), UvfMetadataCodec.newProtectedHeader(), null, Collections.<String, Object>emptyMap(), null, csprng);
	}

	/**
	 * Generates a P-384 key pair, see {@link UvfUnlockedVault#generateRecoveryKey(SecureRandom)}.
	 *
	 * @param csprng A cryptographically secure random number generator
	 * @return The key pair
	 */
	public static KeyPair generateRecoveryKey(SecureRandom csprng) {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
			generator.initialize(new ECGenParameterSpec(Curve.P_384.getStdName()), csprng);
			return generator.generateKeyPair();
		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
			throw new IllegalStateException("P-384 not supported by this JVM", e);
		}
	}

	// CONFIG

	@Override
	public String configFileName() {
		return Constants.CONFIG_FILE_NAME;
	}

	@Override
	public byte[] serializeConfig() {
		assertNotDestroyed();
		if (keyEncryptionKey == null) {
			throw new IllegalStateException("No password or member key set");
		}
		if (recoveryKey == null) {
			throw new IllegalStateException("No recovery key set");
		}
		byte[] payload = seeds.toDecryptedPayload().getBytes(StandardCharsets.UTF_8);
		try {
			return UvfMetadataCodec.serialize(protectedHeader, payload, keyEncryptionKey, keyEncryptionKeyParams, recoveryKey).getBytes(StandardCharsets.UTF_8);
		} finally {
			Arrays.fill(payload, (byte) 0x00);
		}
	}

	@Override
	public String serializedRecoveryKey() {
		assertNotDestroyed();
		if (recoveryKey == null || !recoveryKey.isPrivate()) {
			throw new IllegalStateException("Private recovery key unknown");
		}
		byte[] pkcs8 = RecoveryKeyPkcs8.encode(recoveryKey);
		try {
			return RecoveryKeys.encode(pkcs8, true);
		} finally {
			Arrays.fill(pkcs8, (byte) 0x00);
		}
	}

	@Override
	public Map<String, @Nullable Object> customFields() {
		return seeds.customFields();
	}

	@Override
	public int initialSeedId() {
		return seeds.initialSeedId();
	}

	@Override
	public int latestSeedId() {
		return seeds.latestSeedId();
	}

	@Override
	public Set<Integer> seedIds() {
		return seeds.seedIds();
	}

	@Override
	public int addSeed() {
		assertNotDestroyed();
		return seeds.addSeed(csprng);
	}

	@Override
	public @Nullable String keyEncryptionKid() {
		return keyEncryptionKey == null ? null : keyEncryptionKey.getKeyID();
	}

	@Override
	public @Nullable String recoveryKid() {
		return recoveryKey == null ? null : recoveryKey.getKeyID();
	}

	@Override
	public void setPassword(CharSequence password) {
		setPassword(password, Argon2Params.DEFAULT);
	}

	@Override
	public void setPassword(CharSequence password, Argon2Params params) {
		assertNotDestroyed();
		Map<String, Object> headerParams = Argon2Kdf.newHeaderParams(params, csprng);
		byte[] kek = Argon2Kdf.deriveKey(password, headerParams);
		try {
			this.keyEncryptionKey = new OctetSequenceKey.Builder(kek).keyID(UvfLockedVault.PASSWORD_KID).algorithm(JWEAlgorithm.A256KW).build();
			this.keyEncryptionKeyParams = headerParams;
		} finally {
			Arrays.fill(kek, (byte) 0x00);
		}
	}

	@Override
	public void setMemberKey(SecretKey memberKey) {
		assertNotDestroyed();
		byte[] encoded = memberKey.getEncoded();
		if (encoded == null || encoded.length != Argon2Kdf.KEY_LEN) {
			throw new IllegalArgumentException("Member key must be a 256 bit AES key");
		}
		this.keyEncryptionKey = new OctetSequenceKey.Builder(encoded).keyID(UvfLockedVault.MEMBER_KEY_KID).algorithm(JWEAlgorithm.A256KW).build();
		this.keyEncryptionKeyParams = Collections.emptyMap();
	}

	@Override
	public void setRecoveryKey(KeyPair recoveryKey) {
		assertNotDestroyed();
		if (!(recoveryKey.getPublic() instanceof ECPublicKey && recoveryKey.getPrivate() instanceof ECPrivateKey)) {
			throw new IllegalArgumentException("Not an EC key pair");
		}
		ECPublicKey publicKey = (ECPublicKey) recoveryKey.getPublic();
		if (!Curve.P_384.equals(Curve.forECParameterSpec(publicKey.getParams()))) {
			throw new IllegalArgumentException("Not a P-384 key pair");
		}
		setRecoveryKey(publicKey, (ECPrivateKey) recoveryKey.getPrivate());
	}

	@Override
	public void setRecoveryKey(ECPublicKey recoveryKey) {
		assertNotDestroyed();
		Curve curve = Curve.forECParameterSpec(recoveryKey.getParams());
		if (curve == null) {
			throw new IllegalArgumentException("Unsupported EC curve");
		}
		setRecoveryKey(recoveryKey, null);
	}

	private void setRecoveryKey(ECPublicKey publicKey, @Nullable ECPrivateKey privateKey) {
		Curve curve = Curve.forECParameterSpec(publicKey.getParams());
		try {
			ECKey key = new ECKey.Builder(curve, publicKey).privateKey(privateKey).algorithm(JWEAlgorithm.ECDH_ES_A256KW).build();
			this.recoveryKey = new ECKey.Builder(key).keyID(UvfLockedVault.RECOVERY_KEY_KID_PREFIX + key.computeThumbprint()).build(); // the thumbprint covers the public part only
		} catch (JOSEException e) {
			throw new IllegalArgumentException("Invalid recovery key", e);
		}
	}

	// DIRECTORIES

	UvfNames names() {
		return names;
	}

	@Override
	public VaultDirectory rootDirectory() {
		assertNotDestroyed();
		return new UvfDirectory(this, seeds.initialSeedId(), seeds.rootDirId());
	}

	@Override
	public VaultDirectory newDirectory() {
		assertNotDestroyed();
		byte[] dirId = new byte[Constants.DIR_ID_LEN];
		random.nextBytes(dirId);
		return new UvfDirectory(this, seeds.latestSeedId(), dirId);
	}

	@Override
	public VaultDirectory directory(byte[] dirFileContents) throws AuthenticationFailedException {
		assertNotDestroyed();
		if (dirFileContents.length != layout().ciphertextSize(Constants.DIR_ID_LEN)) {
			throw new IllegalArgumentException(String.format("Invalid dir.uvf length: %s", dirFileContents.length));
		}
		ByteBuffer header = ByteBuffer.wrap(dirFileContents, 0, layout().headerSize());
		try (VaultFileImpl file = parseHeader(header, Constants.DIR_ID_LEN)) {
			ByteBuffer dirId = ByteBuffer.allocate(Constants.DIR_ID_LEN);
			int offset = (int) layout().ciphertextChunkOffset(0);
			file.decryptChunk(ByteBuffer.wrap(dirFileContents, offset, dirFileContents.length - offset), dirId, 0);
			assert !dirId.hasRemaining();
			return new UvfDirectory(this, file.seedId(), dirId.array());
		}
	}

	@Override
	public VaultDirectory directoryFromBackup(byte[] backupFileContents) throws AuthenticationFailedException {
		return directory(backupFileContents); // the backup copy inside the directory has the same format
	}

	/**
	 * Encrypts a directory's id into {@code dir.uvf} contents, using a header bound to the directory's seed.
	 *
	 * @param seedId The directory's seed
	 * @param dirId The directory's id
	 * @return A fresh ciphertext
	 */
	byte[] encryptDirectoryMetadata(int seedId, byte[] dirId) {
		assertNotDestroyed();
		try (VaultFileImpl file = new VaultFileImpl(layout(), codec, codec.createHeader(seedId), 0, false)) {
			ByteBuffer result = ByteBuffer.allocate((int) layout().ciphertextSize(dirId.length));
			result.put(file.encryptedHeader());
			file.encryptChunk(ByteBuffer.wrap(dirId), result, 0);
			assert !result.hasRemaining();
			return result.array();
		}
	}

	// NAMES

	@Override
	public int maxCleartextNameLength(int maxCiphertextNameLength) {
		// an unpadded base64url-encoded AES-SIV ciphertext of n bytes has 16 bytes overhead and expands by 4/3, plus the 4 character extension:
		return (maxCiphertextNameLength - Constants.FILE_EXT.length()) * 3 / 4 - 16;
	}

	// FILES

	@Override
	protected VaultFileImpl newFile() {
		assertNotDestroyed();
		return new VaultFileImpl(layout(), codec, codec.createHeader(seeds.latestSeedId()), 0, false);
	}

	@Override
	protected VaultFileImpl parseHeader(ByteBuffer encryptedHeader, long cleartextSize) throws AuthenticationFailedException {
		assertNotDestroyed();
		FileHeaderParts header = codec.decryptHeader(encryptedHeader);
		return new VaultFileImpl(layout(), codec, header, cleartextSize, true);
	}

	// SYMLINKS

	@Override
	public byte[] encryptSymlinkTarget(String target) {
		return encryptFile(Normalizer.normalize(target, Normalizer.Form.NFC).getBytes(StandardCharsets.UTF_8));
	}

	@Override
	public String decryptSymlinkTarget(byte[] symlinkFileContents) throws AuthenticationFailedException {
		return new String(decryptFile(symlinkFileContents), StandardCharsets.UTF_8);
	}

	// LIFECYCLE

	@Override
	public boolean isDestroyed() {
		return seeds.isDestroyed();
	}

	@Override
	public void destroy() {
		names.destroy();
		seeds.destroy();
		recoveryKey = null; // JCA EC keys cannot be zeroed, at least drop the reference
		keyEncryptionKey = null;
	}

	private void assertNotDestroyed() {
		if (isDestroyed()) {
			throw new IllegalStateException("Vault destroyed.");
		}
	}

}
