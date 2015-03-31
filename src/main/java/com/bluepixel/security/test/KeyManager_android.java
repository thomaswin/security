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
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;



import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;

public class KeyManager_android {

	/**
	 * @param args
	 * @throws NoSuchAlgorithmException 
	 * @throws IOException 
	 * @throws InvalidKeySpecException 
	 * @throws Base64DecodingException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws InvalidKeyException 
	 */
	public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, Base64DecodingException {
		// TODO Auto-generated method stub

		KeyManager_android manager = new KeyManager_android();
		manager.testRetrieve();

	}
	public void testSave() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, 
	IllegalBlockSizeException, BadPaddingException, Base64DecodingException, IOException {

		KeyPair keyPair = generateKeyPair();

		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();

		savePublicKey(publicKey, "my_public_key");
		savePrivateKey(privateKey, "my_private_key");

		String message = "SjzTXjPODC4Di6qrha3k3a9X5J5HRc29f83tuwB0QVKmnkK5cgVXGWyz6B6HCuhSoJRXdBo5Lmyb";
		String encryptedMessage = encryptOrDecrypt(publicKey, message, true);
		String decryptedMessage = encryptOrDecrypt(privateKey, encryptedMessage, false);

		System.out.println("Original message : " + message);
		System.out.println("encryptedMessage : " + encryptedMessage);
		System.out.println("decryptedMessage : " + decryptedMessage);

	}

	public void testRetrieve() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,

	IllegalBlockSizeException, BadPaddingException, Base64DecodingException, InvalidKeySpecException, IOException {
		PublicKey retrievePublicKey = loadPublicKey("my_public_key");
		PrivateKey retrievePrivateKey = loadPrivateKey("my_private_key");

		String message = "12365";
		String encryptedMessage = encryptOrDecrypt(retrievePublicKey, message, true);
		String decryptedMessage = encryptOrDecrypt(retrievePrivateKey, encryptedMessage, false);


		System.out.println("\nOriginal message : " + message);
		System.out.println("encryptedMessage : " + encryptedMessage);
		System.out.println("decryptedMessage : " + decryptedMessage);

		SecretKey secretKey = generateSessionKey(encryptedMessage.toCharArray());
		String encryptedString = encrypt(secretKey, "12345678", "hello world");
		String decryptedString = decrypt(secretKey, "12345678", encryptedString);

		System.out.println("encryptedString : " + encryptedString);
		System.out.println("decryptedString : " + decryptedString);
		
	}

	private SecretKey generateSessionKey(char[] SEKRIT) throws NoSuchAlgorithmException, InvalidKeySpecException{
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
		SecretKey key = keyFactory.generateSecret(new PBEKeySpec(SEKRIT));
		return key;
	}
	
	protected String encrypt(SecretKey key, String salt,  String value ) {
		try {
			final byte[] bytes = value!=null ? value.getBytes() : new byte[0];
			
			Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");
			pbeCipher.init(Cipher.ENCRYPT_MODE, key, new PBEParameterSpec(salt.getBytes(), 20));
			byte[] encryptedByte = pbeCipher.doFinal(bytes);
			String encryptedString = byte2hex(encryptedByte);
			return encryptedString;
		} catch( Exception e ) {
			
		}
		return "";
	}
	
	protected String decrypt(SecretKey key, String salt, String value){
		try {
			final byte[] bytes = value!=null ? hex2Byte(value) : new byte[0];			
			Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");
			pbeCipher.init(Cipher.DECRYPT_MODE, key, new PBEParameterSpec(salt.getBytes(), 20));
			String decryptedString = new String(pbeCipher.doFinal(bytes));
			return decryptedString;
					
		} catch( Exception e) {
			e.printStackTrace();
		}
		return "";
	}
	

	public KeyPair generateKeyPair() throws NoSuchAlgorithmException{

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(1024);
		KeyPair keyPair = keyGen.generateKeyPair();

		return keyPair;
	}

	public PublicKey loadPublicKey(String fileName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
		File filePublicKey = new File(fileName);
		FileInputStream fis = new FileInputStream(filePublicKey);
		byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
		fis.read(encodedPublicKey);
		fis.close();

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

		return publicKey;
	}

	public PrivateKey loadPrivateKey(String fileName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
		File filePrivateKey = new File(fileName);
		FileInputStream fis = new FileInputStream(filePrivateKey);
		byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
		fis.read(encodedPrivateKey);
		fis.close();

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
		PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
		return privateKey;
	}

	public void savePublicKey(PublicKey key, String fileName) throws IOException{
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
				key.getEncoded());
		FileOutputStream fos = new FileOutputStream(fileName);
		fos.write(x509EncodedKeySpec.getEncoded());
		fos.close();
	}


	public void savePrivateKey(PrivateKey key, String fileName) throws IOException{
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
				key.getEncoded());
		FileOutputStream fos = new FileOutputStream(fileName);
		fos.write(pkcs8EncodedKeySpec.getEncoded());
		fos.close();
	}	

	public String encryptOrDecrypt(Key key, String text, boolean encrypt) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, Base64DecodingException {

		Cipher cipher = Cipher.getInstance("RSA");
		if(encrypt){
			byte[] plainTextByte = text.getBytes();
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] cipherText = cipher.doFinal(plainTextByte);
			//String encryptedString = Base64.encode(cipherText);
			String encryptedString = byte2hex(cipherText);
			return encryptedString;
		} else {
			cipher.init(Cipher.DECRYPT_MODE, key);
			//byte[] bytes =  Base64.decode(text);
			byte[] bytes =  hex2Byte(text);
			byte[] decryptedBytes = cipher.doFinal(bytes);
			String decryptedString = new String(decryptedBytes);
			return decryptedString;
		}
	}

	private byte[] hex2Byte(String hexString) {
    
       byte[] bytes = new byte[hexString.length() / 2];
       for (int i = 0; i < bytes.length; i++)
       {
          bytes[i] = (byte) Integer
                .parseInt(hexString.substring(2 * i, 2 * i + 2), 16);
       }
       return bytes;
    }
	
	private String byte2hex(byte[] b) {
    
     // String Buffer can be used instead
       String hs = "";
       String stmp = "";

       for (int n = 0; n < b.length; n++) {
          stmp = (Integer.toHexString(b[n] & 0XFF));

          if (stmp.length() == 1) {
             hs = hs + "0" + stmp;
          } else {
             hs = hs + stmp;
          }
          if (n < b.length - 1) {
             hs = hs + "";
          }
       }
       return hs;
    }

}
