/*
 * Copyright (c).
 *
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Win Tun Lin
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

package com.bluepixel.security.secret;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;




public class AESObfuscator1 implements Obfuscator1{

	private static final String UTF8 = "UTF-8";
	private static final String KEYGEN_ALGORITHM = "PBEWITHSHAAND256BITAES-CBC-BC";
	private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
	private static final String header = "com.android.vending.licensing.AESObfuscator-1|";

	private static final byte[] IV =
		{ 16, 74, 71, -80, 32, 101, -47, 72, 117, -14, 0, -29, 70, 65, -12, 74 };

	private Cipher mEncryptor;
	private Cipher mDecryptor;

	public AESObfuscator1(byte[] salt, String applicationId, String deviceId) {
		try {
			SecretKeyFactory factory = SecretKeyFactory.getInstance(KEYGEN_ALGORITHM);
			KeySpec keySpec = new PBEKeySpec((applicationId + deviceId).toCharArray(),
					salt, 1024, 256);
			SecretKey tmp = factory.generateSecret(keySpec);
			SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
			mEncryptor = Cipher.getInstance(CIPHER_ALGORITHM);
			mEncryptor.init(Cipher.ENCRYPT_MODE, secret, new IvParameterSpec(IV));
			mDecryptor = Cipher.getInstance(CIPHER_ALGORITHM);
			mDecryptor.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(IV));

		} catch (GeneralSecurityException e) {
			throw new RuntimeException("Invalid environment", e);
		}
	}

	@Override
	public String obfuscate(String original, String key) {
		if (original == null) {
			return null;
		}
		try {
			// Header is appended as an integrity check
			return Base64.encode(mEncryptor.doFinal((header + key + original).getBytes(UTF8)));
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException("Invalid environment", e);
		} catch (GeneralSecurityException e) {
			throw new RuntimeException("Invalid environment", e);
		}
	}

	@Override
	public String unobfuscate(String obfuscated, String key) throws ValidationException {
		if (obfuscated == null) {
			return null;
		}
		try {
			String result = new String(mDecryptor.doFinal(Base64.decode(obfuscated)), UTF8);
			// Check for presence of header. This serves as a final integrity check, for cases
			// where the block size is correct during decryption.
			int headerIndex = result.indexOf(header+key);
			if (headerIndex != 0) {
				throw new ValidationException("Header not found (invalid data or key)" + ":" +
						obfuscated);
			}
			return result.substring(header.length()+key.length(), result.length());
		} catch (Base64DecoderException e) {
			throw new ValidationException(e.getMessage() + ":" + obfuscated);
		} catch (IllegalBlockSizeException e) {
			throw new ValidationException(e.getMessage() + ":" + obfuscated);
		} catch (BadPaddingException e) {
			throw new ValidationException(e.getMessage() + ":" + obfuscated);
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException("Invalid environment", e);
		}
	}

}
