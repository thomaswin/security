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

package com.bluepixel.security.test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import com.sun.org.apache.xml.internal.security.utils.Base64;

public class MyKeys {

	private static final int Algorithm_RSA = 1;
	private static final int Algorithm_DSA = 2;

	private static final int default_key_length = 1024;
	
	private static final boolean ENCRYPT = true; 
	private static final boolean DECRYPT = false;

	public static void main(String args[]) throws NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, Base64DecodingException {
		MyKeys manager = new MyKeys();
		KeyPair pair = manager.generateKeyPair(Algorithm_RSA, null);

		String folderPath = "keys";
		String keyFileName = "server";
		manager.print(pair);
		manager.saveKeyPair(pair, folderPath, keyFileName);
		
		//loading key from file
		KeyPair newPair = manager.loadKeyPair(Algorithm_RSA, folderPath, keyFileName);
		manager.print(newPair);

		// encrypt
		String message ="bar";
		String encryptedString = manager.encryptWithPublic(newPair, message);
		encryptedString = manager.encryptOrDecrypt(newPair.getPublic(), message, ENCRYPT);
		System.out.println("encrypted : " + encryptedString);

		// decrypt
		String decryptedString = manager.decryptWithPrivate(newPair, encryptedString);
		decryptedString = manager.encryptOrDecrypt(newPair.getPrivate(), encryptedString, DECRYPT);
		System.out.println("decrypted : " + decryptedString);
	}

	public String encryptWithPublic(KeyPair pair, String plainText) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException{
		
		//Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, pair.getPublic());
		byte[] plainTextByte = plainText.getBytes();
		byte[] cipherText = cipher.doFinal(plainTextByte);
		String encryptedString = Base64.encode(cipherText);
		return encryptedString;
	}

	public String decryptWithPrivate(KeyPair pair, String encryptedText) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, Base64DecodingException{
		
		//Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, pair.getPrivate());
		byte[] bytes =  Base64.decode(encryptedText);
		byte[] decryptedBytes = cipher.doFinal(bytes);
		String decryptedString = new String(decryptedBytes);
		return decryptedString;
	}
	
	public String encryptOrDecrypt(Key key, String text, boolean encrypt) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, Base64DecodingException {
		
		//Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		Cipher cipher = Cipher.getInstance("RSA");
		if(encrypt){
			byte[] plainTextByte = text.getBytes();
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] cipherText = cipher.doFinal(plainTextByte);
			String encryptedString = Base64.encode(cipherText);
			return encryptedString;
		} else {
			cipher.init(Cipher.DECRYPT_MODE, key);
			byte[] bytes =  Base64.decode(text);
			byte[] decryptedBytes = cipher.doFinal(bytes);
			String decryptedString = new String(decryptedBytes);
			return decryptedString;
		}
	}
	
	public KeyPair generateKeyPair(int algorithm, String seed) throws NoSuchAlgorithmException{

		KeyPair keyPair = null;
		switch(algorithm){
		case Algorithm_RSA : 
			keyPair = getRSA_keypair(seed, default_key_length);
			break;
		case Algorithm_DSA :
			keyPair = getDSA_keypair(seed, default_key_length);
			break;
		default:
			break;
		}		
		return keyPair;
	}

	public void saveKeyPair(KeyPair keyPair, String path, String fileName) throws IOException {
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();

		// store Public key
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
				publicKey.getEncoded());
		FileOutputStream fos = new FileOutputStream(path + File.separator + fileName + "_public_key");
		fos.write(x509EncodedKeySpec.getEncoded());
		fos.close();

		// Store Private Key.
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
				privateKey.getEncoded());
		fos = new FileOutputStream(path + File.separator + fileName + "_private_key");
		fos.write(pkcs8EncodedKeySpec.getEncoded());
		fos.close();
	}

	public KeyPair loadKeyPair(int algorithm, String path, String fileName) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException{

		String public_key_fileName = path + File.separator + fileName + "_public_key";
		String private_key_fileName = path + File.separator + fileName + "_private_key";

		// Read Public Key.
		File filePublicKey = new File(public_key_fileName);
		FileInputStream fis = new FileInputStream(public_key_fileName);
		byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
		fis.read(encodedPublicKey);
		fis.close();

		// Read Private Key.
		File filePrivateKey = new File(private_key_fileName);
		fis = new FileInputStream(private_key_fileName);
		byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
		fis.read(encodedPrivateKey);
		fis.close();

		String algo = "";
		switch(algorithm){
		case Algorithm_RSA:
			algo = "RSA";
			break;
		case Algorithm_DSA:
			algo = "DSA";
			break;

		}
		// Generate KeyPair.
		KeyFactory keyFactory = KeyFactory.getInstance(algo);
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
		PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

		return new KeyPair(publicKey, privateKey);
	}

	private KeyPair getRSA_keypair(String seed, int length) throws NoSuchAlgorithmException{
		int key_length = 0;
		if(length == -1){
			key_length = default_key_length;
		} else {
			key_length = length;
		}
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		if(seed != null && seed.equals("")){
			keyGen.initialize(key_length, random);
			random.setSeed(seed.getBytes());
		} else {
			keyGen.initialize(key_length);	
		}

		KeyPair generatedKeyPair = keyGen.genKeyPair();
		return generatedKeyPair;
	}

	private KeyPair getDSA_keypair(String seed, int length){

		return null;
	}

	private void print(KeyPair keyPair) {
		PublicKey pub = keyPair.getPublic();
		System.out.println("Public Key: " + getHexString(pub.getEncoded()));

		PrivateKey priv = keyPair.getPrivate();
		System.out.println("Private Key: " + getHexString(priv.getEncoded()));
	}

	private String getHexString(byte[] b) {
		String result = "";
		for (int i = 0; i < b.length; i++) {
			result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
		}
		return result;
	}

	public String hexToAscii(String s) {
		int n = s.length();
		StringBuilder sb = new StringBuilder(n / 2);
		for (int i = 0; i < n; i += 2) {
			char a = s.charAt(i);
			char b = s.charAt(i + 1);
			sb.append((char) ((hexToInt(a) << 4) | hexToInt(b)));
		}
		return sb.toString();
	}

	private int hexToInt(char ch) {
		if ('a' <= ch && ch <= 'f') { return ch - 'a' + 10; }
		if ('A' <= ch && ch <= 'F') { return ch - 'A' + 10; }
		if ('0' <= ch && ch <= '9') { return ch - '0'; }
		throw new IllegalArgumentException(String.valueOf(ch));
	}
}
