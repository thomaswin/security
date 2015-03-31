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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

import com.example.dungeons.util.Base64;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class Signature_test1 {

	private static final SecureRandom RANDOM = new SecureRandom();

	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub

		create_signature2();
	}
	public static void create_signature2() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, IOException{
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
		keyGen.initialize(1024, random);

		byte[] seed = RANDOM.generateSeed(128);
		random.setSeed(seed);

		// generate public and private key
		KeyPair pair = keyGen.generateKeyPair();
		PrivateKey priv = pair.getPrivate();
		PublicKey pub = pair.getPublic();

		// get signature
		Signature dsa = Signature.getInstance("SHA1withDSA", "SUN"); 
		dsa.initSign(priv);
		
		byte[] data = "test".getBytes("UTF8");
		dsa.update(data);
		byte[] realSig = dsa.sign();
		
		String encodeData = new BASE64Encoder().encode(data);
		String retrieveData = new String(new BASE64Decoder().decodeBuffer(encodeData));
		System.out.println("Data:" + encodeData);
		System.out.println("Data:" + Base64.encode(data));
		System.out.println("Singature:" + new BASE64Encoder().encode(realSig));
		
		dsa.initVerify(pub);
		dsa.update(data);
		System.out.println("Data:" + retrieveData);
		System.out.println(dsa.verify(realSig));
	}


	public static void create_signature() throws Exception {				
		
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(1024);

		KeyPair keyPair = kpg.genKeyPair();
		byte[] data = "test".getBytes("UTF8");

		Signature sig = Signature.getInstance("MD5WithRSA");		

		sig.initSign(keyPair.getPrivate());
		sig.update(data);
		byte[] signatureBytes = sig.sign();
		System.out.println("Singature:" + new BASE64Encoder().encode(signatureBytes));

		sig.initVerify(keyPair.getPublic());
		sig.update(data);

		System.out.println(sig.verify(signatureBytes));
	}
}
