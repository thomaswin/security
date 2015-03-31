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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
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


public class PublicKeyInfrastructureImpl implements ISecurity{

	enum State{
		NOT_READY,
		Ready,
		Running
	};

	private static int keyLength = 1024;
	private static String algorithm = "RSA";
	private static String publicKeyFileName ="";
	private PublicKey publicKey;
	private PrivateKey privateKey;

	private State _state;
	public PublicKeyInfrastructureImpl() {
		_state = State.NOT_READY;
	}

	@Override
	public String decrypt(String cipherText) {
		if(_state == State.Ready) {
			_state = State.Running;
			Cipher cipher = null;
			try {
				cipher.init(Cipher.DECRYPT_MODE, privateKey);
				byte[] cipherByte =  hex2Byte(cipherText);
				byte[] plainByte = cipher.doFinal(cipherByte);
				String plainText = new String(plainByte);
				return plainText;
			} catch (InvalidKeyException e) {
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				e.printStackTrace();
			} catch (BadPaddingException e) {
				e.printStackTrace();
			}
			_state = State.Ready;
		} else {
			throw new IllegalStateException();
		}
		return "";
	}

	@Override
	public String encrypt(String plainText) {
		if(_state == State.Ready) {
			_state = State.Running;
			Cipher cipher;
			try {
				cipher = Cipher.getInstance("RSA");
				byte[] plainByte = plainText.getBytes();
				cipher.init(Cipher.ENCRYPT_MODE, publicKey);
				byte[] cipherByte = cipher.doFinal(plainByte);
				String cipherText = byte2hex(cipherByte);
				return cipherText;
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				e.printStackTrace();
			} catch (BadPaddingException e) {
				e.printStackTrace();
			}
		} else {
			throw new IllegalStateException();
		}
		return "";
	}

	protected void init(){
		if(_state == State.NOT_READY) {
			try {
				publicKey = loadPublicKey(publicKeyFileName);
				//privateKey = loadPrivateKey("");
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (InvalidKeySpecException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
			_state = State.Ready;
		} else {
			throw new IllegalStateException();
		}
	}

	private KeyPair generateKeyPair() throws NoSuchAlgorithmException{
		
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(1024);
		KeyPair keyPair = keyGen.generateKeyPair();

		return keyPair;
	}

	private PublicKey loadPublicKey(String fileName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
		
		
		
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

	private PrivateKey loadPrivateKey(String fileName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
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




















