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
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

public class MessageDigestTest {
	
	/*
	MessageDigest.getInstance("MD5") : Creates the message digest.
	.update(plaintext) : Calculates the message digest with a plaintext string.
	.digest() : Reads the message digest.
	
	KeyGenerator.getInstance("HmacMD5") and .generateKey() : Generates the key.
	Mac.getInstance("HmacMD5") : Creates a MAC object.
	.init(MD5key) : Intializes the MAC object.
	.update(plaintext) and .doFinal() : Calculates the MAC object with a plaintext string.
	*/
	public static void messageDigest() {

		String message = "this is test message";

		try {
			byte[] plainText = message.getBytes("UTF8");

			// get a message digest object using the MD5 algorithm
			MessageDigest messageDigest;
			messageDigest = MessageDigest.getInstance("MD5");

			// print out the provider used
			System.out.println( "\n" + messageDigest.getProvider().getInfo() );

			// calculate the digest and print it out
			messageDigest.update( plainText);
			System.out.println( "\nDigest: " );
			System.out.println( new String( messageDigest.digest(), "UTF8") );
			System.out.println(Util.toHex(new String( messageDigest.digest(), "UTF8")));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}		
	}
	
	public static void messageDigest2() {

		String message = "this is test message";

		try {
			byte[] plainText = message.getBytes("UTF8");

			// get a message digest object using the MD5 algorithm
			MessageDigest messageDigest;
			messageDigest = MessageDigest.getInstance("MD5");
			
			System.out.println("print something");
			// print out the provider used
			System.out.println( "\n" + messageDigest.getProvider().getInfo() );

			// calculate the digest and print it out
			messageDigest.update( plainText);
			System.out.println( "\nDigest: " );
			System.out.println( new String( messageDigest.digest(), "UTF8") );
			System.out.println(Util.toHex(new String( messageDigest.digest(), "UTF8")));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}		
	}

	public static void MessageAuthenticationCodeExample(){
		String message = "this is test message";

		byte[] plainText;
		try {
			plainText = message.getBytes("UTF8");

			// get a key for the HmacMD5 algorithm
			System.out.println( "\nStart generating key" );
			KeyGenerator keyGen = KeyGenerator.getInstance("HmacMD5");
			SecretKey MD5key = keyGen.generateKey();
			System.out.println( "Finish generating key" );

			// get a MAC object and update it with the plaintext
			Mac mac = Mac.getInstance("HmacMD5");
			mac.init(MD5key);
			mac.update(plainText);

			// print out the provider used and the MAC
			System.out.println( "\n" + mac.getProvider().getInfo() );
			System.out.println( "\nMAC: " );
			System.out.println( new String( mac.doFinal(), "UTF8") );
			System.out.println(Util.toHex(new String( mac.doFinal(), "UTF8")));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}
	}

}
