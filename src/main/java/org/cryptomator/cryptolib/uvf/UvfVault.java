package org.cryptomator.cryptolib.uvf;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.UvfKeyEncryptionKey;
import org.cryptomator.cryptolib.api.UvfLockedVault;
import org.cryptomator.cryptolib.api.UvfRecoveryKey;
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
import java.security.SecureRandom;
import java.text.Normalizer;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

/**
 * An unlocked Unified Vault Format vault.
 *
 * @implNote Recipient algorithms, the password recipient's Argon2 parameters and the recovery key's public JWK live in the payload's {@code recipientDetails} ({@link UvfSeeds}); this class
 * only holds the key material. {@link #serializeConfig()} returns the cached serialization while nothing changed; {@code rotationRequired} is set by every setter and cleared by
 * {@link #addSeed()}, the recipients given at creation need no rotation because the initial seed is fresh.
 */
public final class UvfVault extends AbstractUnlockedVault implements UvfUnlockedVault {

	private final UvfSeeds seeds;
	private final JWEHeader protectedHeader;
	private final SecureRandom csprng;
	private final SecureRandom random;
	private final UvfContentCodec codec;
	private final UvfNames names;
	private @Nullable OctetSequenceKey keyEncryptionKey; // password-derived or member key, null after recovery until set
	private @Nullable ECKey recoveryKey; // public key, plus the private part if set as key pair or recovered with it
	private byte @Nullable [] serialized; // the last serialization (or the file the vault was unlocked from) while nothing changed, else null
	private boolean rotationRequired = false; // a recipient was replaced and no seed added since

	UvfVault(UvfSeeds seeds, JWEHeader protectedHeader, byte @Nullable [] serialized, @Nullable OctetSequenceKey keyEncryptionKey, @Nullable ECKey recoveryKey, SecureRandom csprng) {
		this(seeds, protectedHeader, serialized, keyEncryptionKey, recoveryKey, csprng, ReseedingSecureRandom.create(csprng));
	}

	/**
	 * @param seeds The decrypted payload
	 * @param protectedHeader The protected header to serialize with
	 * @param serialized The file this vault was unlocked from, or {@code null} for a new vault (whose initial seed counts as freshly added)
	 * @param keyEncryptionKey The key encryption key, {@code null} after recovery
	 * @param recoveryKey The recovery key (public, optionally with private part), {@code null} for a new vault
	 * @param csprng A cryptographically secure random number generator
	 * @param random The random number generator for nonces and directory ids (visible for testing)
	 */
	UvfVault(UvfSeeds seeds, JWEHeader protectedHeader, byte @Nullable [] serialized, @Nullable OctetSequenceKey keyEncryptionKey, @Nullable ECKey recoveryKey, SecureRandom csprng, SecureRandom random) {
		super(UvfContentCodec.LAYOUT);
		this.seeds = seeds;
		this.protectedHeader = protectedHeader;
		this.serialized = serialized == null ? null : serialized.clone();
		this.keyEncryptionKey = keyEncryptionKey;
		this.recoveryKey = recoveryKey;
		this.csprng = csprng;
		this.random = random;
		this.codec = new UvfContentCodec(seeds, random);
		this.names = new UvfNames(seeds);
	}

	/**
	 * Creates a new vault, see {@link UvfUnlockedVault#create(SecureRandom, UvfKeyEncryptionKey, UvfRecoveryKey)}.
	 *
	 * @param csprng A cryptographically secure random number generator
	 * @param keyEncryptionKey The password or member key
	 * @param recoveryKey The recovery key
	 * @return The new, unlocked vault
	 */
	public static UvfVault create(SecureRandom csprng, UvfKeyEncryptionKey keyEncryptionKey, UvfRecoveryKey recoveryKey) {
		return create(UvfSeeds.create(csprng), keyEncryptionKey, recoveryKey, csprng, ReseedingSecureRandom.create(csprng));
	}

	// visible for testing: a new vault around given seeds; its initial seed is fresh, so the initial recipients need no rotation
	static UvfVault create(UvfSeeds seeds, UvfKeyEncryptionKey keyEncryptionKey, UvfRecoveryKey recoveryKey, SecureRandom csprng, SecureRandom random) {
		UvfVault vault = new UvfVault(seeds, UvfMetadataCodec.newProtectedHeader(), null, null, null, csprng, random);
		vault.applyKeyEncryptionKey(keyEncryptionKey);
		vault.applyRecoveryKey(recoveryKey);
		return vault;
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
		if (rotationRequired) {
			throw new IllegalStateException("A key was replaced, call addSeed() before serializing");
		}
		if (serialized != null) {
			return serialized.clone();
		}
		byte[] payload = seeds.toDecryptedPayload().getBytes(StandardCharsets.UTF_8);
		try {
			serialized = UvfMetadataCodec.serialize(protectedHeader, payload, seeds.recipientDetails(), keyEncryptionKey).getBytes(StandardCharsets.UTF_8);
			return serialized.clone();
		} finally {
			Arrays.fill(payload, (byte) 0x00);
		}
	}

	private void markDirty() {
		serialized = null;
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
	public Map<Integer, byte[]> seedDigests() {
		assertNotDestroyed();
		return Collections.unmodifiableMap(seeds.seedDigests());
	}

	@Override
	public int addSeed() {
		assertNotDestroyed();
		int seedId = seeds.addSeed(csprng);
		markDirty();
		rotationRequired = false;
		return seedId;
	}

	@Override
	public @Nullable String keyEncryptionKid() {
		return keyEncryptionKey == null ? null : keyEncryptionKey.getKeyID();
	}

	@Override
	public void setKeyEncryptionKey(UvfKeyEncryptionKey keyEncryptionKey) {
		assertNotDestroyed();
		applyKeyEncryptionKey(keyEncryptionKey);
		markDirty();
		rotationRequired = true;
	}

	@Override
	public void setRecoveryKey(UvfRecoveryKey recoveryKey) {
		assertNotDestroyed();
		applyRecoveryKey(recoveryKey);
		markDirty();
		rotationRequired = true;
	}

	// derives or copies the key and replaces the recipient entry; the key encryption key is either the password-derived or the member key, so setting one removes the other
	private void applyKeyEncryptionKey(UvfKeyEncryptionKey keyEncryptionKey) {
		OctetSequenceKey key;
		Map<String, Object> vendorFields;
		SecretKey memberKey = keyEncryptionKey.memberKey();
		CharSequence password = keyEncryptionKey.password();
		if (memberKey != null) {
			key = new OctetSequenceKey.Builder(memberKey).keyID(keyEncryptionKey.kid()).algorithm(JWEAlgorithm.A256KW).build();
			vendorFields = Collections.emptyMap();
		} else if (password != null && keyEncryptionKey.argon2Params() != null) {
			vendorFields = Argon2Kdf.newHeaderParams(keyEncryptionKey.argon2Params(), csprng);
			byte[] kek = Argon2Kdf.deriveKey(password, vendorFields);
			try {
				key = new OctetSequenceKey.Builder(kek).keyID(keyEncryptionKey.kid()).algorithm(JWEAlgorithm.A256KW).build();
			} finally {
				Arrays.fill(kek, (byte) 0x00);
			}
		} else {
			throw new IllegalArgumentException("Key encryption key has neither password nor member key");
		}
		seeds.removeRecipient(UvfLockedVault.PASSWORD_KID);
		seeds.removeRecipient(UvfLockedVault.MEMBER_KEY_KID);
		seeds.putRecipient(key.getKeyID(), new UvfSeeds.RecipientDetails(JWEAlgorithm.A256KW.getName(), null, vendorFields));
		this.keyEncryptionKey = key;
	}

	private void applyRecoveryKey(UvfRecoveryKey recoveryKey) {
		Curve curve = Curve.forECParameterSpec(recoveryKey.publicKey().getParams());
		if (curve == null) {
			throw new IllegalArgumentException("Unsupported EC curve");
		}
		ECKey key;
		try {
			key = new ECKey.Builder(curve, recoveryKey.publicKey()).privateKey(recoveryKey.privateKey()).keyID(UvfLockedVault.RECOVERY_KEY_KID).algorithm(JWEAlgorithm.ECDH_ES_A256KW).build();
		} catch (IllegalStateException e) {
			throw new IllegalArgumentException("Invalid recovery key", e);
		}
		seeds.putRecipient(UvfLockedVault.RECOVERY_KEY_KID, new UvfSeeds.RecipientDetails(JWEAlgorithm.ECDH_ES_A256KW.getName(), key.toPublicJWK().toJSONObject(), Collections.<String, Object>emptyMap()));
		this.recoveryKey = key;
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
		try (VaultFileImpl file = parseHeader(header, Constants.DIR_ID_LEN, Constants.KDF_CONTEXT_DIR_HEADER)) {
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
	 * Encrypts a directory's id into {@code dir.uvf} contents, using a directory metadata header bound to the directory's seed.
	 *
	 * @param seedId The directory's seed
	 * @param dirId The directory's id
	 * @return A fresh ciphertext
	 */
	byte[] encryptDirectoryMetadata(int seedId, byte[] dirId) {
		assertNotDestroyed();
		return encryptWith(newFile(seedId, Constants.KDF_CONTEXT_DIR_HEADER), dirId);
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
		return newFile(seeds.latestSeedId(), Constants.KDF_CONTEXT_FILE_HEADER);
	}

	private VaultFileImpl newFile(int seedId, byte[] headerContext) {
		return new VaultFileImpl(layout(), codec, codec.createHeader(seedId, headerContext), 0, false);
	}

	@Override
	protected VaultFileImpl parseHeader(ByteBuffer encryptedHeader, long cleartextSize) throws AuthenticationFailedException {
		return parseHeader(encryptedHeader, cleartextSize, Constants.KDF_CONTEXT_FILE_HEADER);
	}

	private VaultFileImpl parseHeader(ByteBuffer encryptedHeader, long cleartextSize, byte[] headerContext) throws AuthenticationFailedException {
		assertNotDestroyed();
		FileHeaderParts header = codec.decryptHeader(encryptedHeader, headerContext);
		return new VaultFileImpl(layout(), codec, header, cleartextSize, true);
	}

	// SYMLINKS

	@Override
	public byte[] encryptSymlinkTarget(String target) {
		assertNotDestroyed();
		byte[] cleartext = Normalizer.normalize(target, Normalizer.Form.NFC).getBytes(StandardCharsets.UTF_8);
		return encryptWith(newFile(seeds.latestSeedId(), Constants.KDF_CONTEXT_SYMLINK_HEADER), cleartext);
	}

	@Override
	public String decryptSymlinkTarget(byte[] symlinkFileContents) throws AuthenticationFailedException {
		assertNotDestroyed();
		byte[] cleartext = decryptWith((header, size) -> parseHeader(header, size, Constants.KDF_CONTEXT_SYMLINK_HEADER), symlinkFileContents);
		return new String(cleartext, StandardCharsets.UTF_8);
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
		serialized = null;
	}

	private void assertNotDestroyed() {
		if (isDestroyed()) {
			throw new IllegalStateException("Vault destroyed.");
		}
	}

}
