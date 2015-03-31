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
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.util.Date;

import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateIssuerName;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateSubjectName;
import sun.security.x509.CertificateValidity;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;



//http://docs.oracle.com/javase/1.5.0/docs/api/java/security/KeyStore.html
public class KeystoreTest {
	public static void main (String[] args) throws Exception {
		new KeystoreTest().createCertificate();
	}
	public void test1() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableEntryException{
		//To rely on the default type:
		//KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());		

		//provide a specific keystore type:
		//KeyStore ks = KeyStore.getInstance("JKS");


		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());

		// get user password and file input stream
		ProtectionParameter password = getPassword();
		FileInputStream fis = new FileInputStream("keyStoreName");
		ks.load(fis, password.toString().toCharArray());
		fis.close();

		// get my private key
		KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)ks.getEntry("privateKeyAlias", password);	    
		PrivateKey myPrivateKey = pkEntry.getPrivateKey();

		// save my secret key
		javax.crypto.SecretKey mySecretKey = null;
		KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(mySecretKey);
		ks.setEntry("secretKeyAlias", skEntry, password);

		// store away the keystore
		FileOutputStream fos = new FileOutputStream("newKeyStoreName");
		ks.store(fos, password.toString().toCharArray());
		fos.close();
	}

	private static ProtectionParameter getPassword() {
		return null;
	}

	private void keystore() throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {

		String keystoreFilename = "my.keystore";
		char[] password = "password".toCharArray();
		String alias = "alias";

		FileInputStream fIn = new FileInputStream(keystoreFilename);
		KeyStore keystore = KeyStore.getInstance("JKS");

		keystore.load(fIn, password);

		Certificate cert =  keystore.getCertificate(alias);
		System.out.println(cert);
	}

	private void createKeystore() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {

		KeyStore ks = KeyStore.getInstance("JKS");
		/*
		 * LOAD THE STORE
		 * The first time you're doing this (i.e. the keystore does not
		 * yet exist - you're creating it), you HAVE to load the keystore
		 * from a null source with null password. Before any methods can
		 * be called on your keystore you HAVE to load it first. Loading
		 * it from a null source and null password simply creates an empty
		 * keystore. At a later time, when you want to verify the keystore
		 * or get certificates (or whatever) you can load it from the
		 * file with your password.
		 */
		ks.load( null, null );
		//GET THE FILE CONTAINING YOUR CERTIFICATE
		FileInputStream fis = new FileInputStream( "MyCert.cer" );
		BufferedInputStream bis = new BufferedInputStream(fis);
		//I USE x.509 BECAUSE THAT'S WHAT keytool CREATES
		CertificateFactory cf = CertificateFactory.getInstance( "X.509" );
		//NOTE: THIS IS java.security.cert.Certificate NOT java.security.Certificate
		Certificate cert = null;
		/*
		 * I ONLY HAVE ONE CERT, I JUST USED "while" BECAUSE I'M JUST
		 * DOING TESTING AND WAS TAKING WHATEVER CODE I FOUND IN
		 * THE API DOCUMENTATION. I COULD HAVE DONE AN "if", BUT I
		 * WANTED TO SHOW HOW YOU WOULD HANDLE IT IF YOU GOT A CERT
		 * FROM VERISIGN THAT CONTAINED MULTIPLE CERTS
		 */
		//GET THE CERTS CONTAINED IN THIS ROOT CERT FILE
		while ( bis.available() > 0 )
		{
			cert = cf.generateCertificate( bis );
			ks.setCertificateEntry( "SGCert", cert );
		}
		//ADD TO THE KEYSTORE AND GIVE IT AN ALIAS NAME
		ks.setCertificateEntry( "SGCert", cert );
		//SAVE THE KEYSTORE TO A FILE
		/*
		 * After this is saved, I believe you can just do setCertificateEntry
		 * to add entries and then not call store. I believe it will update
		 * the existing store you load it from and not just in memory.
		 */
		ks.store( new FileOutputStream( "NewClientKeyStore" ), "MyPass".toCharArray() );

	}

	private void createCertificate() throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException, IOException, InvalidKeyException, NoSuchProviderException, SignatureException{
		String keystoreFile = "keyStoreFile.bin";
		String caAlias = "caAlias";
		String certToSignAlias = "cert";
		String newAlias = "newAlias";

		char[] password = new char[]{'a','b','c','d','e','f','g','h'};
		char[] caPassword = new char[]{'a','b','c','d','e','f','g','h'};
		char[] certPassword = new char[]{'a','b','c','d','e','f','g','h'};

		FileInputStream input = new FileInputStream(keystoreFile);
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(input, password);
		input.close();

		PrivateKey caPrivateKey = (PrivateKey) keyStore.getKey(caAlias, caPassword);
		Certificate caCert = keyStore.getCertificate(caAlias);

		byte[] encoded = caCert.getEncoded();
		X509CertImpl caCertImpl = new X509CertImpl(encoded);

		X509CertInfo caCertInfo = (X509CertInfo) caCertImpl.get(X509CertImpl.NAME + "."
				+ X509CertImpl.INFO);

		X500Name issuer = (X500Name) caCertInfo.get(X509CertInfo.SUBJECT + "."
				+ CertificateIssuerName.DN_NAME);

		Certificate cert = keyStore.getCertificate(certToSignAlias);
		PrivateKey privateKey = (PrivateKey) keyStore.getKey(certToSignAlias, certPassword);
		encoded = cert.getEncoded();
		X509CertImpl certImpl = new X509CertImpl(encoded);
		X509CertInfo certInfo = (X509CertInfo) certImpl
				.get(X509CertImpl.NAME + "." + X509CertImpl.INFO);

		Date firstDate = new Date();
		Date lastDate = new Date(firstDate.getTime() + 365 * 24 * 60 * 60 * 1000L);
		CertificateValidity interval = new CertificateValidity(firstDate, lastDate);

		certInfo.set(X509CertInfo.VALIDITY, interval);

		certInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(
				(int) (firstDate.getTime() / 1000)));

		certInfo.set(X509CertInfo.ISSUER + "." + CertificateSubjectName.DN_NAME, issuer);

		AlgorithmId algorithm = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);
		certInfo.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algorithm);
		X509CertImpl newCert = new X509CertImpl(certInfo);

		newCert.sign(caPrivateKey, "MD5WithRSA");

		keyStore.setKeyEntry(newAlias, privateKey, certPassword,
				new Certificate[] { newCert });

		FileOutputStream output = new FileOutputStream(keystoreFile);
		keyStore.store(output, password);
		output.close();

	}

}
