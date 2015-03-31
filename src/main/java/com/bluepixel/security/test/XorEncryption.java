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

import java.util.Calendar;

import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import com.sun.org.apache.xml.internal.security.utils.Base64;

public class XorEncryption {

	static final String key = "encrypt_key";

	public static void main(String[] args) throws Base64DecodingException {
		// TODO Auto-generated method stub
		String s1 = "Somebody complimented my driving today ? \"testing\" ";		
		long start = Calendar.getInstance().getTimeInMillis();
		String s2 = Base64.encode(encryptString(s1).getBytes());
		String s3 = decryptString(new String(Base64.decode(s2)));
		System.out.println(Calendar.getInstance().getTimeInMillis() - start);
		System.out.println("Original string:  " + s1);
		System.out.println("Encrypted string: " + s2);
		System.out.println("Decrypted string: " + s3);
	}

	private static String encryptString (String plainText) {
		StringBuffer sb = new StringBuffer(plainText);

		int lenPlainText = plainText.length();
		int lenKey = key.length();

		for ( int i = 0, j = 0; i < lenPlainText; i++, j++ ) {
			if ( j >= lenKey )
				j = 0;  // Wrap 'round to beginning of key string.
			// XOR the chars together. Must cast back to char to avoid compile error.
			sb.setCharAt(i, (char)(plainText.charAt(i) ^ key.charAt(j))); 
		}
		return sb.toString();
	}

	private static String decryptString(String cipherText){
		return encryptString(cipherText);
	}
}












