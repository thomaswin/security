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
import com.bluepixel.security.Base64;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;




/**
 * 
 http://docs.oracle.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html#AppA

 if a block cipher is used and the message length is not a multiple of the block
 length, the last block must be padded with bytes to yield a full block size.
 There are many ways to pad a block, such as using all zeroes or ones. 
 In this tutorial, we'll be using PKCS5 padding for private key encryption and 
 PKCS1 for public key encryption.

 With PKCS5, a short block is padded with a repeating byte whose value represents
 the number of remaining bytes. We won't be discussing padding algorithms 
 further in this tutorial, but for your information, JDK 1.4 supports the 
 following padding techniques:
 - No padding
 - PKCS5
 - OAEP
 - SSL3

 Modes: Specifying how encryption works
 A given cipher can be used in a variety of modes.
 Modes allow you to specify how encryption will work.
 For example, you can allow the encryption of one block to be dependent on the encryption of the previous block,
 or you can make the encryption of one block independent of any other blocks.
 The mode you choose depends on your needs and you must consider the trade-offs
 (security, ability to parallel process, and tolerance to errors in both the plaintext and the ciphertext). 
 Selection of modes is beyond the scope of this tutorial (see Resources for further reading), 
 but again, for your information, the Java platform supports the following modes:
 - ECB (Electronic Code Book)
 - CBC (Cipher Block Chaining)
 - CFB (Cipher Feedback Mode)
 - OFB (Output Feedback Mode)
 - PCBC (Propagating Cipher Block Chaining)

 - DES. DES (Data Encryption Standard) was invented by IBM in the 1970s and adopted by the U.S. 
   government as a standard. It is a 56-bit block cipher.

 - TripleDES. This algorithm is used to deal with the growing weakness of a 56-bit key while 
   leveraging DES technology by running plaintext through the DES algorithm three times, with two keys, giving an effective key strength of 112 bits. TripleDES is sometimes known as DESede (for encrypt, decrypt, and encrypt, which are the three phases).

 - AES. AES (Advanced Encryption Standard) replaces DES as the U.S. standard. 
   It was invented by Joan Daemen and Vincent Rijmen and is also known as the Rinjdael algorithm. It is a 128-bit block cipher with key lengths of 128, 192, or 256 bits.

 - RC2, RC4, and RC5. These are algorithms from a leading encryption security company, RSA Security.

 - Blowfish. This algorithm was developed by Bruce Schneier and is a block cipher with variable key 
   lengths from 32 to 448 bits (in multiples of 8), and was designed for efficient implementation in software for microprocessors.

 - PBE. PBE (Password Based Encryption) can be used in combination with a variety of message digest 
   and private key algorithms.

 KeyGenerator.getInstance("DES") , .init(56) , and .generateKey() : Generates the key.
 Cipher.getInstance("DES/ECB/PKCS5Padding") : Creates the Cipher object (specifying the algorithm, mode, and padding).
 .init(Cipher.ENCRYPT_MODE, key) : Initializes the Cipher object.
 .doFinal(plainText) : Calculates the ciphertext with a plaintext string.
 .init(Cipher.DECRYPT_MODE, key) : Decrypts the ciphertext.
 .doFinal(cipherText) : Computes the ciphertext.

 "algorithm/mode/padding" or
 "algorithm"

 */
public class PrivateKeyTest {

	public static void main (String[] args) throws Exception {
		generateAESwithOwnprivateKey();
	}
	public static void testDES() throws Exception{
		String message = "this is test messagethis is test messagethis is test messagethis is test messagethis is test messagethis is test messagethis is test messagethis is test messagethis is test messagethis is test messagethis is test messagethis is test messagethis is test messagethis is test messagethis is test messagethis is test messagethis is test message" +
				"this is test messagethis is test messagethis is test messagethis is test messagethis is test messagethis is test messagethis is test messagethis is test messagethis is test messagethis is test messagethis is test messagethis is test messagethis is test messagethis is test messagethis is test messagethis is test messagethis is test message" +
				"this is test messagethis is test messagethis is test messagethis is test messagethis is test messagethis is test messagethis is test messagethis is test messagethis is test messagethis is test messagethis is test messagethis is test messagethis is test messagethis is test messagethis is test messagethis is test messagethis is test message";
		byte[] plainText = message.getBytes("UTF8");

		// get a DES private key
		System.out.println( "\nStart generating DES key" );
		KeyGenerator keyGen = KeyGenerator.getInstance("DES");
		keyGen.init(56);
		Key key = keyGen.generateKey();		
		System.out.println( "Finish generating DES key" );
		
		// get a DES cipher object and print the provider
		Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
		System.out.println( "\n" + cipher.getProvider().getInfo() );

		// encrypt using the key and the plaintext
		System.out.println( "\nStart encryption" );
		cipher.init(Cipher.ENCRYPT_MODE, key);
		long start = System.currentTimeMillis();
		byte[] cipherText = cipher.doFinal(plainText);
		System.out.println( "Finish encryption: "  );
		System.out.println(Base64.encode(key.getEncoded()));
		System.out.println((System.currentTimeMillis() - start));		

		// decrypt the ciphertext using the same key
		System.out.println( "\nStart decryption" );
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] newPlainText = cipher.doFinal(cipherText);
		System.out.println( "Finish decryption: " );

		System.out.println( new String(newPlainText, "UTF8") );
	}

	private static void generateAESwithOwnprivateKey() throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		String username = "bob@google.org";
		String password = "Password1";
		String secretID = "BlahBlahBlah";
		String SALT2 = "deliciously salty";

		byte[] key = (SALT2 + username + password).getBytes("UTF-8");
		MessageDigest sha = MessageDigest.getInstance("SHA-1");
		key = sha.digest(key);
		key = Arrays.copyOf(key, 16); // use only first 128 bit

		SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
		
		// Instantiate the cipher
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

		byte[] encrypted = cipher.doFinal("This is just an example".getBytes());
		System.out.println("encrypted key (Base 64)    : " + Base64.encodeWebSafe(key, false) + " -  key length : " + key.length * 8);
		System.out.println("encrypted string (Hex) 	   : " + Util.toHexString(encrypted));
		System.out.println("encrypted string (Base 64) : " + Base64.encodeWebSafe(encrypted, false));
				
		
		cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
		byte[] original = cipher.doFinal(encrypted);
		String originalString = new String(original);
		System.out.println("Original string: " +  originalString );
	}

	@SuppressWarnings("unused")
	private void generateAnotherMethod2() throws InvalidKeySpecException, NoSuchAlgorithmException,
	NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, 
	IllegalBlockSizeException, BadPaddingException {
		PBEKeySpec pbeKeySpec;
		PBEParameterSpec pbeParamSpec;
		SecretKeyFactory keyFac;

		// Salt
		byte[] salt = {
				(byte)0xc7, (byte)0x73, (byte)0x21, (byte)0x8c,
				(byte)0x7e, (byte)0xc8, (byte)0xee, (byte)0x99
		};

		// Iteration count
		int count = 20;

		// Create PBE parameter set
		pbeParamSpec = new PBEParameterSpec(salt, count);

		// Prompt user for encryption password.
		// Collect user password as char array (using the
		// "readPassword" method from above), and convert
		// it into a SecretKey object, using a PBE key
		// factory.
		System.out.print("Enter encryption password:  ");
		System.out.flush();
		pbeKeySpec = new PBEKeySpec("password".toCharArray());
		keyFac = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
		SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);

		// Create PBE Cipher
		Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");

		// Initialize PBE Cipher with key and parameters
		pbeCipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);

		// Our cleartext
		byte[] cleartext = "This is another example".getBytes();

		// Encrypt the cleartext
		byte[] ciphertext = pbeCipher.doFinal(cleartext);
	}
	private SecretKey generateKey() throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(256); //128 default; 192 and 256 also possible
		SecretKey key = keyGenerator.generateKey();		
		return key; 
	}    
	private void saveKey(SecretKey key, File file) throws IOException  {
		byte[] encoded = key.getEncoded();
		String data = new BigInteger(1, encoded).toString(16);
		writeStringToFile(file, data);
	}


	private SecretKey loadKey(File file) throws IOException {
		String hex = new String(readFileToByteArray(file));
		byte[] encoded = new BigInteger(hex, 16).toByteArray();

		SecretKey key = new SecretKeySpec(encoded, "AES");
		return key;
	}

	private void writeStringToFile(File file, String data) {

	}
	private String readFileToByteArray(File file) {
		// TODO Auto-generated method stub
		return null;
	}
}







