/*******************************************************************************
 * Copyright (c) 2015, 2016 Sebastian Stenzel and others.
 * This file is licensed under the terms of the MIT license.
 * See the LICENSE.txt file for more info.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v1;

import org.cryptomator.cryptolib.api.KeyFile;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

class KeyFileImpl extends KeyFile {

	@Expose
	@SerializedName("scryptSalt")
	byte[] scryptSalt;

	@Expose
	@SerializedName("scryptCostParam")
	int scryptCostParam;

	@Expose
	@SerializedName("scryptBlockSize")
	int scryptBlockSize;

	@Expose
	@SerializedName("primaryMasterKey")
	byte[] encryptionMasterKey;

	@Expose
	@SerializedName("hmacMasterKey")
	byte[] macMasterKey;

	@Expose
	@SerializedName("versionMac")
	byte[] versionMac;

}