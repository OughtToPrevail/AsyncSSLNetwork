/*
Copyright 2019 https://github.com/OughtToPrevail

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

/**
 * A {@link SSLContext} factory.
 * <b>IMPORTANT NOTE: THIS SHOULD ONLY BE USED FOR TESTING!!!</b>
 */
public class SSLContextFactory
{
	/**
	 * Default protocol for {@link SSLContext}
	 */
	private static final String DEFAULT_PROTOCOL = "TLSv1.2";
	
	/**
	 * Creates a {@link SSLContext} with the {@link #DEFAULT_PROTOCOL} and stores it's keystores in the specified file location with the specified password as the password.
	 *
	 * @param file to store keystores in
	 * @param password to protect the keystore with
	 * @return the created {@link SSLContext}
	 */
	public static SSLContext createContext(String file, char[] password)
			throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException
	{
		SSLContext context = SSLContext.getInstance(DEFAULT_PROTOCOL);
		KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		keyManagerFactory.init(createKeyStore(file, password), password);
		trustManagerFactory.init(createKeyStore(file, password));
		KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();
		TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
		context.init(keyManagers, trustManagers, null);
		return context;
	}
	
	/**
	 * Creates a key store with the specified parameters.
	 *
	 * @param file to store the keystore in
	 * @param password for the keystore
	 * @return the keystore
	 */
	private static KeyStore createKeyStore(String file, char[] password)
			throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException
	{
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		File fileObj = new File(file);
		if(!fileObj.exists())
		{
			if(!fileObj.createNewFile())
			{
				throw new IllegalStateException("Failed to create file: '" + file + "'!");
			}
			keyStore.load(null, password);
			try(FileOutputStream out = new FileOutputStream(fileObj))
			{
				keyStore.store(out, password);
			}
			return keyStore;
		}
		try(FileInputStream in = new FileInputStream(fileObj))
		{
			keyStore.load(in, password);
		}
		return keyStore;
	}
}