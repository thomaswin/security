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
import java.math.BigInteger;

import javax.xml.bind.DatatypeConverter;


public class Util {

	public static String toHex(String arg) throws UnsupportedEncodingException {
		return String.format("%x", new BigInteger(arg.getBytes("UTF8")));
	}

	public static String toHexString(byte[] array) {
		return DatatypeConverter.printHexBinary(array);
	}

	public static byte[] toByteArray(String s) {
		return DatatypeConverter.parseHexBinary(s);
	}

	public static String convertStringToHex(String str){

		char[] chars = str.toCharArray();

		StringBuffer hex = new StringBuffer();
		for(int i = 0; i < chars.length; i++){
			hex.append(Integer.toHexString((int)chars[i])).append(" ");
		}
		return hex.toString();
	}

	public static String convertHexToString(String hex){

		hex = hex.replaceAll("\\s", "");
		StringBuilder sb = new StringBuilder();
		StringBuilder temp = new StringBuilder();

		//49204c6f7665204a617661 split into two characters 49, 20, 4c...
		for( int i=0; i<hex.length()-1; i+=2 ){

			//grab the hex in pairs
			String output = hex.substring(i, (i + 2));

			//convert hex to decimal
			int decimal = Integer.parseInt(output, 16);
			
			//convert the decimal to character
			sb.append((char)decimal);

			temp.append(decimal);
		}
		System.out.println("Decimal : " + temp.toString());

		return sb.toString();
	}
	public static void testStringToHex() {

		System.out.println("\n***** Convert ASCII to Hex *****");
		String str = "I Love Java!";  
		System.out.println("Original input : " + str);
		String hex = Util.convertStringToHex(str);
		
		System.out.println("Hex : " + hex);

		System.out.println("\n***** Convert Hex to ASCII *****");
		System.out.println("Hex : " + hex);
		System.out.println("ASCII : " + Util.convertHexToString(hex));
	}
}
