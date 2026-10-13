package org.cryptomator.cryptolib.uvf;

import com.google.common.base.Preconditions;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObjectJSON;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.UvfRecipient;
import org.cryptomator.cryptolib.api.UvfUnlockedVault;
import org.cryptomator.cryptolib.api.VaultDirectory;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;
import org.cryptomator.cryptolib.common.ReseedingSecureRandom;
import org.cryptomator.cryptolib.internal.AbstractUnlockedVault;
import org.cryptomator.cryptolib.internal.FileHeaderParts;
import org.cryptomator.cryptolib.internal.VaultFileImpl;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * An unlocked Unified Vault Format vault.
 */
public final class UvfVault extends AbstractUnlockedVault implements UvfUnlockedVault {

	private final UvfSeeds seeds;
	private final DestroyableSecretKey contentKey; // the JWE's CEK, kept to re-encrypt the metadata after changes
	private final JWEHeader protectedHeader;
	private final List<JWEObjectJSON.Recipient> recipients;
	private final SecureRandom csprng;
	private final SecureRandom random;
	private final UvfContentCodec codec;
	private final UvfNames names;

	UvfVault(UvfSeeds seeds, SecretKey contentKey, JWEHeader protectedHeader, List<JWEObjectJSON.Recipient> recipients, SecureRandom csprng) {
		this(seeds, contentKey, protectedHeader, recipients, csprng, ReseedingSecureRandom.create(csprng));
	}

	// visible for testing
	UvfVault(UvfSeeds seeds, SecretKey contentKey, JWEHeader protectedHeader, List<JWEObjectJSON.Recipient> recipients, SecureRandom csprng, SecureRandom random) {
		super(UvfContentCodec.LAYOUT);
		this.seeds = seeds;
		this.contentKey = new DestroyableSecretKey(contentKey.getEncoded(), "AES");
		this.protectedHeader = protectedHeader;
		this.recipients = recipients;
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
		return new UvfVault(UvfSeeds.create(csprng), UvfMetadataCodec.newContentKey(csprng), UvfMetadataCodec.newProtectedHeader(), new ArrayList<JWEObjectJSON.Recipient>(), csprng);
	}

	// CONFIG

	@Override
	public String configFileName() {
		return Constants.CONFIG_FILE_NAME;
	}

	@Override
	public byte[] serializeConfig() {
		assertNotDestroyed();
		if (recipients.isEmpty()) {
			throw new IllegalStateException("Vault has no recipients, nobody could unlock it");
		}
		byte[] payload = seeds.toDecryptedPayload().getBytes(StandardCharsets.UTF_8);
		try (DestroyableSecretKey cek = contentKey.copy()) {
			return UvfMetadataCodec.serialize(protectedHeader, payload, cek, recipients).getBytes(StandardCharsets.UTF_8);
		} finally {
			java.util.Arrays.fill(payload, (byte) 0x00);
		}
	}

	@Override
	public List<UvfRecipient> recipients() {
		List<UvfRecipient> result = new ArrayList<>();
		for (JWEObjectJSON.Recipient recipient : recipients) {
			result.add(new UvfRecipientImpl(recipient));
		}
		return Collections.unmodifiableList(result);
	}

	@Override
	public Map<String, Object> customFields() {
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
	public void addPasswordRecipient(String kid, CharSequence password, int iterationCount) {
		assertNotDestroyed();
		try (DestroyableSecretKey cek = contentKey.copy()) {
			recipients.add(UvfMetadataCodec.wrapWithPassword(kid, password, iterationCount, cek, csprng));
		}
	}

	@Override
	public void addEcdhRecipient(String kid, ECPublicKey publicKey) {
		assertNotDestroyed();
		try (DestroyableSecretKey cek = contentKey.copy()) {
			recipients.add(UvfMetadataCodec.wrapWithPublicKey(kid, publicKey, cek, csprng));
		}
	}

	@Override
	public void addKeyWrapRecipient(String kid, SecretKey keyEncryptionKey) {
		assertNotDestroyed();
		try (DestroyableSecretKey cek = contentKey.copy()) {
			recipients.add(UvfMetadataCodec.wrapWithKeyEncryptionKey(kid, keyEncryptionKey, cek));
		}
	}

	@Override
	public void removeRecipient(String kid) {
		assertNotDestroyed();
		Iterator<JWEObjectJSON.Recipient> iter = recipients.iterator();
		while (iter.hasNext()) {
			JWEObjectJSON.Recipient recipient = iter.next();
			if (recipient.getUnprotectedHeader() != null && kid.equals(recipient.getUnprotectedHeader().getKeyID())) {
				Preconditions.checkState(recipients.size() > 1, "Can not remove the last recipient");
				iter.remove();
				return;
			}
		}
		throw new IllegalArgumentException("No recipient with kid " + kid);
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
		Preconditions.checkArgument(dirFileContents.length == layout().ciphertextSize(Constants.DIR_ID_LEN), "Invalid dir.uvf length: %s", dirFileContents.length);
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
		contentKey.destroy();
		seeds.destroy();
	}

	private void assertNotDestroyed() {
		if (isDestroyed()) {
			throw new IllegalStateException("Vault destroyed.");
		}
	}

	// visible for testing
	static SecretKey contentKey(byte[] raw) {
		return new SecretKeySpec(raw, "AES");
	}

}
