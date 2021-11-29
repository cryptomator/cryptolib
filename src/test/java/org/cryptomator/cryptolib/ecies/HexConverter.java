package org.cryptomator.cryptolib.ecies;

import com.google.common.io.BaseEncoding;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.params.converter.ArgumentConversionException;
import org.junit.jupiter.params.converter.ArgumentConverter;

class HexConverter implements ArgumentConverter {

	@Override
	public byte[] convert(Object source, ParameterContext context) throws ArgumentConversionException {
		if (source == null) {
			return new byte[0];
		} else if (source instanceof String) {
			return BaseEncoding.base16().lowerCase().decode((String) source);
		} else {
			return null;
		}
	}
}
