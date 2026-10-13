package org.cryptomator.cryptolib.cvf8;

import com.google.common.base.Preconditions;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.CipherCombo;
import org.cryptomator.cryptolib.api.Cvf8UnlockedVault;
import org.cryptomator.cryptolib.api.CvfMasterkey;
import org.cryptomator.cryptolib.api.VaultDirectory;
import org.cryptomator.cryptolib.common.ReseedingSecureRandom;
import org.cryptomator.cryptolib.internal.AbstractUnlockedVault;
import org.cryptomator.cryptolib.internal.FileHeaderParts;
import org.cryptomator.cryptolib.internal.VaultFileImpl;

import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.UUID;

/**
 * An unlocked Cryptomator Vault Format 8 vault.
 */
public final class Cvf8Vault extends AbstractUnlockedVault implements Cvf8UnlockedVault {

	private final CvfMasterkey masterkey;
	private final String vaultId;
	private final URI keyId;
	private final CipherCombo cipherCombo;
	private final int shorteningThreshold;
	private final Cvf8ContentCodec codec;
	private final Cvf8Names names;

	Cvf8Vault(CvfMasterkey masterkey, String vaultId, URI keyId, CipherCombo cipherCombo, int shorteningThreshold, SecureRandom csprng) {
		this(masterkey, vaultId, keyId, cipherCombo, shorteningThreshold, codec(cipherCombo, masterkey, ReseedingSecureRandom.create(csprng)));
	}

	// visible for testing
	Cvf8Vault(CvfMasterkey masterkey, String vaultId, URI keyId, CipherCombo cipherCombo, int shorteningThreshold, Cvf8ContentCodec codec) {
		super(codec.layout());
		this.masterkey = masterkey;
		this.vaultId = vaultId;
		this.keyId = keyId;
		this.cipherCombo = cipherCombo;
		this.shorteningThreshold = shorteningThreshold;
		this.codec = codec;
		this.names = new Cvf8Names(masterkey);
	}

	private static Cvf8ContentCodec codec(CipherCombo cipherCombo, CvfMasterkey masterkey, SecureRandom random) {
		switch (cipherCombo) {
			case SIV_CTRMAC:
				return new CtrMacCodec(masterkey, random);
			case SIV_GCM:
				return new GcmCodec(masterkey, random);
			default:
				throw new IllegalArgumentException("Unsupported cipher combo " + cipherCombo);
		}
	}

	/**
	 * Creates a new vault, see {@link Cvf8UnlockedVault#create(CvfMasterkey, int, SecureRandom)}.
	 *
	 * @param masterkey The vault's masterkey
	 * @param shorteningThreshold Ciphertext names longer than this are shortened
	 * @param csprng A cryptographically secure random number generator
	 * @return The new, unlocked vault
	 */
	public static Cvf8Vault create(CvfMasterkey masterkey, int shorteningThreshold, SecureRandom csprng) {
		Preconditions.checkArgument(shorteningThreshold > 0, "shortening threshold must be positive");
		return new Cvf8Vault(masterkey.copy(), UUID.randomUUID().toString(), Constants.DEFAULT_KEY_ID, CipherCombo.SIV_GCM, shorteningThreshold, csprng);
	}

	// CONFIG

	@Override
	public String configFileName() {
		return Constants.CONFIG_FILE_NAME;
	}

	@Override
	public byte[] serializeConfig() {
		assertNotDestroyed();
		return Cvf8ConfigCodec.sign(vaultId, keyId, cipherCombo, shorteningThreshold, masterkey).getBytes(StandardCharsets.US_ASCII);
	}

	@Override
	public CvfMasterkey masterkey() {
		return masterkey;
	}

	@Override
	public String vaultId() {
		return vaultId;
	}

	@Override
	public URI keyId() {
		return keyId;
	}

	@Override
	public CipherCombo cipherCombo() {
		return cipherCombo;
	}

	@Override
	public int shorteningThreshold() {
		return shorteningThreshold;
	}

	// DIRECTORIES

	Cvf8Names names() {
		return names;
	}

	@Override
	public VaultDirectory rootDirectory() {
		assertNotDestroyed();
		return new Cvf8Directory(this, Constants.ROOT_DIR_ID);
	}

	@Override
	public VaultDirectory newDirectory() {
		assertNotDestroyed();
		return new Cvf8Directory(this, UUID.randomUUID().toString());
	}

	@Override
	public VaultDirectory directory(byte[] dirFileContents) {
		assertNotDestroyed();
		Preconditions.checkArgument(dirFileContents.length > 0, "Directory file must not be empty");
		Preconditions.checkArgument(dirFileContents.length <= Constants.MAX_DIR_ID_LENGTH, "Directory file exceeds %s bytes", Constants.MAX_DIR_ID_LENGTH);
		return new Cvf8Directory(this, new String(dirFileContents, StandardCharsets.UTF_8));
	}

	@Override
	public VaultDirectory directoryFromBackup(byte[] backupFileContents) throws AuthenticationFailedException {
		assertNotDestroyed();
		byte[] dirId = decryptFile(backupFileContents);
		Preconditions.checkArgument(dirId.length <= Constants.MAX_DIR_ID_LENGTH, "Directory id exceeds %s bytes", Constants.MAX_DIR_ID_LENGTH);
		return new Cvf8Directory(this, new String(dirId, StandardCharsets.UTF_8));
	}

	// NAMES

	@Override
	public int maxCleartextNameLength(int maxCiphertextNameLength) {
		// a base64url-encoded AES-SIV ciphertext of n bytes has 16 bytes overhead and expands by 4/3, plus the 4 character extension:
		return (Math.min(shorteningThreshold, maxCiphertextNameLength) - Constants.FILE_EXT.length()) / 4 * 3 - 16;
	}

	@Override
	public boolean isShortenedName(String nameOnDisk) {
		return nameOnDisk.endsWith(Constants.SHORTENED_FILE_EXT);
	}

	@Override
	public String shortenName(String ciphertextName) {
		return Cvf8Names.shorten(ciphertextName);
	}

	// FILES

	@Override
	protected VaultFileImpl newFile() {
		assertNotDestroyed();
		return new VaultFileImpl(layout(), codec, codec.createHeader(), 0, false);
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
		return encryptFile(target.getBytes(StandardCharsets.UTF_8));
	}

	@Override
	public String decryptSymlinkTarget(byte[] symlinkFileContents) throws AuthenticationFailedException {
		return new String(decryptFile(symlinkFileContents), StandardCharsets.UTF_8);
	}

	// LIFECYCLE

	@Override
	public boolean isDestroyed() {
		return masterkey.isDestroyed();
	}

	@Override
	public void destroy() {
		masterkey.destroy();
	}

	private void assertNotDestroyed() {
		if (isDestroyed()) {
			throw new IllegalStateException("Vault destroyed.");
		}
	}

}
