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

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import com.example.dungeons.util.Base64;

/*
 	The following two algorithms are used in public key encryption:
 	-RSA. This algorithm is the most popular public key cipher, but it's not supported in JDK 1.4. 
  	You must use a third-party library like BouncyCastle to get this support.

 	-Diffie-Hellman. This algorithm is technically known as a key-agreement algorithm . 
  	It cannot be used for encryption, but can be used to allow two parties to derive a 
  	secret key by sharing information over a public channel. This key can then be used for private key encryption. 

  	KeyPairGenerator.getInstance("RSA") , .initialize(1024) , and .generateKeyPair() : Generates the key pair.
  	Cipher.getInstance("RSA/ECB/PKCS1Padding") Creates a Cipher object (specifying the algorithm, mode, and padding).
  		.init(Cipher.ENCRYPT_MODE, key.getPublic()) : Initializes the Cipher object. 
  		.doFinal(plainText) : Calculates the ciphertext with a plaintext string.
  		.init(Cipher.DECRYPT_MODE, key.getPrivate()) and .doFinal(cipherText) : Decrypts the ciphertext.
 */


public class PublicKeyTest {
	public static void main (String[] args) throws Exception {
		test1();
	}
	public static void test1() throws Exception{
		String message = "this is test message";
		byte[] plainText = message.getBytes("UTF8");

		// generate an RSA key
		System.out.println( "\nStart generating RSA key" );
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(1024);
		KeyPair key = keyGen.generateKeyPair();
		System.out.println( "Finish generating RSA key" );
		System.out.println(key.getPublic().toString());
		System.out.println(key.getPrivate().toString());

		// get an RSA cipher object and print the provider   
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		System.out.println( "\n" + cipher.getProvider().getInfo() );

		// encrypt the plaintext using the public key
		System.out.println( "\nStart encryption" );
		cipher.init(Cipher.ENCRYPT_MODE, key.getPublic());
		long start = System.currentTimeMillis();
		String cipherText = Base64.encode(cipher.doFinal(plainText));
		
		System.out.println( "Finish encryption: " + (System.currentTimeMillis()- start));		
		System.out.println(cipherText);
		
		// decrypt the ciphertext using the private key
		System.out.println( "\nStart decryption" );
		cipher.init(Cipher.DECRYPT_MODE, key.getPrivate());
		byte[] newPlainText = cipher.doFinal(Base64.decode(cipherText));		
		System.out.println( "Finish decryption: " );
		System.out.println( new String(newPlainText, "UTF8") );

	}
	
	public static void test2() throws Exception{
		String message = "secret_key";
		byte[] plainText = message.getBytes("UTF8");	
		
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(1024);
		KeyPair key = keyGen.generateKeyPair();
		
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		
	}

	public static void anotheMethod() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair kp = kpg.genKeyPair();
		Key publicKey = kp.getPublic();
		Key privateKey = kp.getPrivate();		
		

		KeyFactory fact = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec pub = fact.getKeySpec(kp.getPublic(), RSAPublicKeySpec.class);
		RSAPrivateKeySpec priv = fact.getKeySpec(kp.getPrivate(), RSAPrivateKeySpec.class);

		saveToFile("public.key.data", pub.getModulus(),pub.getPublicExponent());
		saveToFile("private.key.data", priv.getModulus(),priv.getPrivateExponent());

		//RSAPublicKeySpec(BigInteger modulus, BigInteger publicExponent);

	}

	private static void saveToFile(String filename, BigInteger modulus, BigInteger publicExponent) throws IOException {
		ObjectOutputStream oout = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(filename)));
		try {
			oout.writeObject(modulus);
			oout.writeObject(publicExponent);			
		} catch (Exception e) {
			throw new IOException("Unexpected error", e);
		} finally {
			oout.close();
		}
	}

	private static void saveToFile(String filename, byte[] key) throws IOException {
		FileOutputStream keyfos = new FileOutputStream(filename);
		keyfos.write(key);
		keyfos.close();
	}

	public static byte[] convert(Object obj) throws IOException {
		ObjectOutputStream os = null;

		ByteArrayOutputStream byteStream = new ByteArrayOutputStream();		
		os = new ObjectOutputStream(new BufferedOutputStream(byteStream));
		os.flush();
		os.writeObject(obj);
		os.flush();
		byte[] sendBuf = byteStream.toByteArray();
		os.close();
		return sendBuf;
	}
	
	private static void readFromFile(String filename) throws FileNotFoundException, IOException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchProviderException {
		ObjectInputStream objectInputStream = new ObjectInputStream(new BufferedInputStream(new FileInputStream(filename)));
		convert(objectInputStream.readObject());		
		//oout.readObject();
	}
	
	
	public void testPublicKeyTransfer() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, IOException, InvalidKeySpecException {
		
		/************************* Public Key ******************************/
		// Initialize the Key-Pair Generator
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
		keyGen.initialize(1024, random);
		random.setSeed(1234);
		
		// Generate the Pair of Keys 
		KeyPair pair 	= keyGen.generateKeyPair();
		PrivateKey priv = pair.getPrivate();
		PublicKey pub 	= pair.getPublic();
		
		
		/* save the public key in a file */
		byte[] key = pub.getEncoded();
		FileOutputStream keyfos = new FileOutputStream("suepk");
		keyfos.write(key);
		keyfos.close();
		
		
		// Input and Convert the Encoded Public Key Bytes
		FileInputStream keyfis = new FileInputStream("suepk");
		byte[] encKey = new byte[keyfis.available()];  
		keyfis.read(encKey);
		keyfis.close();
		
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);
		KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");
		PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
		
		//PrivateKey privKey = keyFactory.generatePrivate(pubKeySpec);
		
		
		/************************* Signature  ******************************/
		// Get a Signature Object:
		Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
		// Initialize the Signature Object
		dsa.initSign(priv);
		
		// Supply the Signature Object the Data to Be Signed 
		FileInputStream fis = new FileInputStream("hello world data");
		BufferedInputStream bufin = new BufferedInputStream(fis);
		byte[] buffer = new byte[1024];
		int len;
		while ((len = bufin.read(buffer)) >= 0) {
		    dsa.update(buffer, 0, len);
		};
		bufin.close();
		
		// Generate the Signature
		byte[] realSig = dsa.sign();
		
		// Save the Signature and the Public Key in Files
		/* save the signature in a file */
		FileOutputStream sigfos = new FileOutputStream("sig");
		sigfos.write(realSig);
		sigfos.close();
		
		
		// Input the Signature Bytes
		FileInputStream sigfis = new FileInputStream("sig");
		byte[] sigToVerify = new byte[sigfis.available()]; 
		sigfis.read(sigToVerify);
		sigfis.close();
		
		
	}
}

















