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
import java.security.*;
import javax.crypto.*;
//
// This program demonstrates the digital signature technique at the
// primative level by generating a message digest of the plaintext

// and signing it with an RSA private key, to create the signature.
// To verify the signature, the message digest is again generated from
// the plaintext and compared with the decryption of the signature

public class DigitalSignatureTest {

	public static void main (String[] args) throws Exception {
		String message = "this is test message";
		byte[] plainText = message.getBytes("UTF8");		

		// get an MD5 message digest object and compute the plaintext digest
		MessageDigest messageDigest = MessageDigest.getInstance("MD5");
		System.out.println( "\n" + messageDigest.getProvider().getInfo() );
		messageDigest.update( plainText );
		byte[] md = messageDigest.digest();
		System.out.println( "\nDigest: " );
		System.out.println( new String( md, "UTF8") );
		
		// generate an RSA keypair
		System.out.println( "\nStart generating RSA key" );
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(1024);
		KeyPair key = keyGen.generateKeyPair();
		System.out.println( "Finish generating RSA key" );
		
		// get an RSA cipher and list the provider
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		System.out.println( "\n" + cipher.getProvider().getInfo() );
		
		// encrypt the message digest with the RSA private key
		// to create the signature
		System.out.println( "\nStart encryption" );
		cipher.init(Cipher.ENCRYPT_MODE, key.getPrivate());
		byte[] cipherText = cipher.doFinal(md);
		System.out.println( "Finish encryption: " );
		System.out.println( new String(cipherText, "UTF8") );
		
		// to verify, start by decrypting the signature with the
		// RSA private key
		System.out.println( "\nStart decryption" );
		cipher.init(Cipher.DECRYPT_MODE, key.getPublic());

		byte[] newMD = cipher.doFinal(cipherText);
		System.out.println( "Finish decryption: " );
		System.out.println( new String(newMD, "UTF8") );
		
		// then, recreate the message digest from the plaintext
		// to simulate what a recipient must do
		System.out.println( "\nStart signature verification" );
		messageDigest.reset();
		messageDigest.update(plainText);
		byte[] oldMD = messageDigest.digest();
		
		// verify that the two message digests match
		int len = newMD.length;
		if (len > oldMD.length) {
			System.out.println( "Signature failed, length error");
			System.exit(1);
		}
		for (int i = 0; i < len; ++i)
			if (oldMD[i] != newMD[i]) {
				System.out.println( "Signature failed, element error" );
				System.exit(1);
			}
		System.out.println( "Signature verified" );
	}
}
