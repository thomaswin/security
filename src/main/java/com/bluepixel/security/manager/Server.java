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

package com.bluepixel.security.manager;

import org.apache.commons.lang3.RandomStringUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.util.concurrent.ConcurrentHashMap;



public class Server {

	public static final String DEFAULT_ALGORITHM 		 = "RSA";
	public static final String DEFAULT_ALGORITHM_PADDING = "RSA/ECB/PKCS1Padding";
	public static final int DEFAULT_KEY_LENGTH 		= 1024;
	public static final int DEFAULT_MAX_KEY			= 50;
	
	public ConcurrentHashMap<String, String> secretKeys;
	public String publicKey;
	public String privateKey;
	
	private void init() {
		generateKey();
	}
	private void generateKey() {
		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance(DEFAULT_ALGORITHM);
			keyGen.initialize(DEFAULT_KEY_LENGTH);
			KeyPair keypair = keyGen.generateKeyPair();
			PublicKey pbKey = keypair.getPublic();
			PrivateKey piKey = keypair.getPrivate();
			
			publicKey = Base64.encodeWebSafe(pbKey.getEncoded(), false);
			privateKey = Base64.encodeWebSafe(piKey.getEncoded(), false);
			
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			
			cipher.init(Cipher.ENCRYPT_MODE, piKey);
			
			secretKeys = new ConcurrentHashMap<String, String>();
			String [] randomKeys  = generateRandomWords(10);
			for (String key: randomKeys) {
				String cipherText = Base64.encodeWebSafe(cipher.doFinal(key.getBytes()), false);
				secretKeys.put(key, cipherText);
			}
		} catch (NoSuchAlgorithmException e) {
		} catch (InvalidKeyException e) {
		} catch (NoSuchPaddingException e) {
		} catch (IllegalBlockSizeException e) {
		} catch (BadPaddingException e) {
		}
	}
	
	
	
	private String[] generateRandomWords(int numberOfWords) {
		System.out.println("Server -> generateRandomWords  : " + numberOfWords);
		String[] randomStrings = new String[numberOfWords];
				
		for(int i = 0; i < numberOfWords; i++) {	    	
			randomStrings[i] = new String(RandomStringUtils.randomAlphanumeric(64));
		}		    
		return randomStrings;
	}
	
	private PrivateKey getPrivateKey(String privateKeyString) {
		return null;
	}
	
	private PublicKey getPublicKey(String publicKeyString) {		
		return null;
	}	
}




