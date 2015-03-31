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





import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.bluepixel.security.Base64;
import org.apache.commons.lang3.RandomStringUtils;



public class ServerClient_test {

	private static String message = "This is secret message 1 ";


	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, Base64DecoderException, InvalidKeySpecException {
		// TODO Auto-generated method stub
		//		ServerClient_test test = new ServerClient_test();
		//		Key key = test.getSecretKey();		
		//		String plainKey = Base64.encodeWebSafe(key.getEncoded(), false);
		//		String cipherMessage = test.encryptMessage(key, message);
		//
		//		System.out.println("*********** Sender *************");
		//		System.out.println("Plain Text : " + cipherMessage);
		//		System.out.println("cipher Text : " + cipherMessage);
		//		System.out.println("secret key : " + plainKey);
		//
		//		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		//		keyGen.initialize(1024);
		//		KeyPair keyPair = keyGen.generateKeyPair();
		//		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		//		cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
		//		String cipherText = Base64.encodeWebSafe(cipher.doFinal(plainKey.getBytes()), false);
		//		System.out.println("secret key  (encrypted with PKI): " + cipherText);
		//
		//
		//		cipher.init(Cipher.DECRYPT_MODE, keyPair.getPublic());
		//		byte[] plainKeyByte = cipher.doFinal(Base64.decodeWebSafe(cipherText));		
		//		String original = test.decryptMessage(getKeyFromString(new String(plainKeyByte)), cipherMessage);
		//
		//		System.out.println("\n*********** Receiver *************");
		//		System.out.println("secret key  (encrypted with PKI): " + cipherText);
		//		System.out.println("secret key : " + new String(plainKey));
		//		System.out.println("original message : " + original);
		//
		//
		//		System.out.println("cipher key : " + cipherText);
		//		System.out.println("cipher message : " + cipherMessage);

		System.out.println("\n*********** Test Client authentication *************");
		//Server.init();
		//		try {
		//			Client.connect();
		//		} catch (NoSuchProviderException e) {
		//
		//		}

		List<String> str = decodePoly("ie}Fq}wxRj@uBFUd@yBLm@h@_C^mBp@sC`AeEH[BENq@?AFYDO?C?AFW@A@IFUPy@TcAFWF[~@aEhAgF@S?M?aAAQ?YAe@?]?e@");
		for (int i = 0 ; i < str.size(); i++) {
			System.out.println(i + " " + str.get(i));
		}

	}



	private static List<String> decodePoly(String encoded) {

		List<String> poly = new ArrayList<String>();
		int index = 0, len = encoded.length();
		int lat = 0, lng = 0;
		while (index < len) {
			int b, shift = 0, result = 0;
			do {
				b = encoded.charAt(index++) - 63;
				result |= (b & 0x1f) << shift;
				shift += 5;
			} while (b >= 0x20);
			int dlat = ((result & 1) != 0 ? ~(result >> 1) : (result >> 1));
			lat += dlat;
			shift = 0;
			result = 0;
			do {
				b = encoded.charAt(index++) - 63;
				result |= (b & 0x1f) << shift;
				shift += 5;
			} while (b >= 0x20);
			int dlng = ((result & 1) != 0 ? ~(result >> 1) : (result >> 1));
			lng += dlng;			
			String p = String.format("%f, %f",  (((double) lat / 1E5)), (((double) lng / 1E5)));
			poly.add(p);
		} 

		return poly;
	}


	public static class Server {
		static KeyPair keyPair;
		static String[] secrectCodes;
		static ConcurrentHashMap<String, String> secretHashMap;

		public static void init() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(1024);			
			keyPair = keyGen.generateKeyPair();	

			secrectCodes =  generateRandomWords(50);

			PrivateKey privateKey = keyPair.getPrivate();
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

			cipher.init(Cipher.ENCRYPT_MODE, privateKey);

			secretHashMap = new ConcurrentHashMap<String, String>();
			for (String code: secrectCodes) {
				String cipherText = Base64.encodeWebSafe(cipher.doFinal(code.getBytes()), false);
				secretHashMap.put(code, cipherText);
			}			
		}

		private static String[] generateRandomWords(int numberOfWords) {
			System.out.println("Server -> generateRandomWords  : " + numberOfWords);
			String[] randomStrings = new String[numberOfWords];

			for(int i = 0; i < numberOfWords; i++) {	    	
				randomStrings[i] = new String(RandomStringUtils.randomAlphanumeric(64));
			}		    
			return randomStrings;
		}

		public static SecurityCode getSecurityCode() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

			PublicKey publicKey = keyPair.getPublic();

			int randomIndex = (int) (Math.random() * secrectCodes.length);
			String code = secrectCodes[randomIndex];			
			String cipherText = secretHashMap.get(code);
			String publicKeyString = Base64.encodeWebSafe(publicKey.getEncoded(), false);

			SecurityCode securityMessage = new SecurityCode();
			securityMessage.publicKey = publicKeyString;
			securityMessage.secrectString = cipherText;

			System.out.println("Server -> choosen Code : " + code);
			System.out.println("Server -> publicKey : " + publicKeyString);
			System.out.println("Server -> cipherText : " + cipherText);
			return securityMessage;
		}

		public static String doAuthenticate(String plainString, String cipherString_, String nounce) {
			String cipherString = secretHashMap.get(plainString);
			if ( cipherString != null && cipherString.equals(cipherString_)) {
				return encryptString(nounce, "This is real message. You crack it with public key");
			} else {
				return "error";	
			}

		}

		private static String encryptString (String key, String plainText) {

			StringBuffer sb = new StringBuffer(plainText);

			int lenPlainText = plainText.length();
			int lenKey = key.length();

			for ( int i = 0, j = 0; i < lenPlainText; i++, j++ ) {
				if ( j >= lenKey )
					j = 0;
				sb.setCharAt(i, (char)(plainText.charAt(i) ^ key.charAt(j))); 
			}
			String cipherText = Base64.encodeWebSafe(sb.toString().getBytes(), false);

			return cipherText;
		}
	}

	public static class Client {

		public static boolean connect() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, Base64DecoderException, NoSuchProviderException, InvalidKeySpecException {
			SecurityCode securityCode = Server.getSecurityCode();

			byte[] publicKeybyte = Base64.decodeWebSafe(securityCode.publicKey);
			X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKeybyte);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, pubKey);

			byte[] plainKeyByte = cipher.doFinal(Base64.decodeWebSafe(securityCode.secrectString));
			String secretString = new String (plainKeyByte);


			String cipherMessage  = Server.doAuthenticate(secretString, securityCode.secrectString, "my_nounce");
			String plainText = decryptString("my_nounce", cipherMessage);
			System.out.println("Client -> choosen code : " + secretString);
			System.out.println("Client -> Server Cipher Message : " + cipherMessage);
			System.out.println("Client -> Server Plain Message : " + plainText);
			System.out.println("Client -> Server Cipher Message : " + cipherMessage.getBytes().length);
			return false;
		}

		private static String decryptString (String key, String text) throws Base64DecoderException {
			String plainText = new String(Base64.decodeWebSafe(text));
			StringBuffer sb = new StringBuffer(plainText);

			int lenPlainText = plainText.length();
			int lenKey = key.length();

			for ( int i = 0, j = 0; i < lenPlainText; i++, j++ ) {
				if ( j >= lenKey )
					j = 0;
				sb.setCharAt(i, (char)(plainText.charAt(i) ^ key.charAt(j))); 
			}

			return sb.toString();
		}
	}

	private static class SecurityCode {		
		public String publicKey;
		public String secrectString;
	}

	private static SecretKey  getSecretKey() throws NoSuchAlgorithmException{
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(128);
		SecretKey key = keyGenerator.generateKey();
		return key;		
	}


	private static Key getKeyFromString(String encryptedKey) throws NoSuchAlgorithmException, InvalidKeySpecException, Base64DecoderException {
		SecretKey key = new SecretKeySpec(Base64.decodeWebSafe(encryptedKey), "AES");		
		return key;
	}

	private String encryptMessage(Key secretKey, String message) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {		
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		byte[] encrypted = cipher.doFinal(message.getBytes());
		String cipherMessage = Base64.encodeWebSafe(encrypted, false);
		return cipherMessage;
	}

	private String decryptMessage(Key secretKey, String message) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, Base64DecoderException {
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.DECRYPT_MODE, secretKey);

		byte[] originalByte = cipher.doFinal(Base64.decodeWebSafe(message));
		String original = new String(originalByte);
		return original;
	}
}












