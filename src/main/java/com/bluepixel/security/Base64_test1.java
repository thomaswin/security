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

package com.bluepixel.security;

import java.io.UnsupportedEncodingException;

public class Base64_test1 {

	/**
	 * @param args
	 * @throws UnsupportedEncodingException 
	 * @throws Base64DecoderException 
	 */
	public static void main(String[] args) throws UnsupportedEncodingException, Base64DecoderException {
		// TODO Auto-generated method stub
		
		
		
		String message = "hello world?test=123&url=www.yahoo.com.sg/testmessage";
		String encodedString = Base64.encode(message.getBytes("UTF-8"));
		String decodedString = new String(Base64.decode(encodedString), "UTF-8");
		System.out.println(encodedString);
		System.out.println(decodedString);
		System.out.println(Base64.encodeWebSafe(message.getBytes("UTF-8"), false));
		System.out.println(Base64.encodeWebSafe(message.getBytes("UTF-8"), true));
	}

}
