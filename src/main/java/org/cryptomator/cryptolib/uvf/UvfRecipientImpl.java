package org.cryptomator.cryptolib.uvf;

import com.nimbusds.jose.JWEObjectJSON;
import org.cryptomator.cryptolib.api.UvfRecipient;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Read-only view of one entry of the JWE {@code recipients} array.
 */
final class UvfRecipientImpl implements UvfRecipient {

	private final JWEObjectJSON.Recipient recipient;

	UvfRecipientImpl(JWEObjectJSON.Recipient recipient) {
		this.recipient = recipient;
	}

	JWEObjectJSON.Recipient recipient() {
		return recipient;
	}

	@Override
	public String kid() {
		return recipient.getUnprotectedHeader() == null ? null : recipient.getUnprotectedHeader().getKeyID();
	}

	@Override
	public String alg() {
		return UvfMetadataCodec.alg(recipient);
	}

	@Override
	public Map<String, Object> header() {
		if (recipient.getUnprotectedHeader() == null) {
			return Collections.emptyMap();
		}
		return Collections.unmodifiableMap(new LinkedHashMap<>(recipient.getUnprotectedHeader().toJSONObject()));
	}

	@Override
	public String toString() {
		return "UvfRecipient[kid=" + kid() + ", alg=" + alg() + "]";
	}

}
