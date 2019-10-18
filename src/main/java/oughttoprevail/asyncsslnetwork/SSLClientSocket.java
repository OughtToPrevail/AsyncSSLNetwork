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
package oughttoprevail.asyncsslnetwork;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

import oughttoprevail.asyncnetwork.client.ClientSocket;
import oughttoprevail.asyncnetwork.util.DisconnectionType;
import oughttoprevail.asyncnetwork.util.writer.client.ClientWriter;
import oughttoprevail.asyncsslnetwork.rw.SSLReader;
import oughttoprevail.asyncsslnetwork.rw.SSLWriter;

/**
 * An {@link SSLClientSocket} is a {@link ClientSocket} which handles SSL for both reading writing.
 */
public class SSLClientSocket extends ClientSocket implements SSLSocket
{
	/**
	 * The {@link SSLSocketBase} is the SSL controller of this socket,
	 * it will handle all the SSL related tasks.
	 */
	private SSLSocketBase sslSocketBase;
	
	public SSLClientSocket(SSLContext sslContext)
	{
		this(ClientSocket.DEFAULT_BUFFER_SIZE, sslContext);
	}
	
	public SSLClientSocket(int bufferSize, SSLContext sslContext)
	{
		this(bufferSize, new SSLReader(), new SSLWriter(new ClientWriter()), sslContext);
	}
	
	public SSLClientSocket(int bufferSize, SSLReader reader, SSLWriter writer, SSLContext sslContext)
	{
		super(bufferSize, reader, writer);
		sslSocketBase = new SSLSocketBase(this, writer, sslContext, true, null);
		reader.init(sslSocketBase);
	}
	
	/**
	 * Whether the closure will be forced or initiate a SSL sequence
	 */
	private boolean forceClosure;
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	protected boolean preClose(DisconnectionType disconnectionType)
	{
		if(forceClosure)
		{
			return true;
		}
		if(sslSocketBase.closeSSL(disconnectionType))
		{
			return super.preClose(disconnectionType);
		}
		return false;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void beginHandshake()
	{
		sslSocketBase.beginHandshake();
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void onHandshakeComplete(Runnable onHandshakeComplete)
	{
		sslSocketBase.onHandshakeComplete(onHandshakeComplete);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean hasHandshakeBegun()
	{
		return sslSocketBase.hasHandshakeBegun();
	}
	
	/**
	 * {@inheritDoc}
	 */
	public boolean isHandshakeComplete()
	{
		return sslSocketBase.isHandshakeComplete();
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public SSLEngine getSSLEngine()
	{
		return sslSocketBase.getSSLEngine();
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public SSLContext getSSLContext()
	{
		return sslSocketBase.getSSLContext();
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public SSLSocketBase getSSLSocketBase()
	{
		return sslSocketBase;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void forceClosure()
	{
		forceClosure = true;
		sslSocketBase.forceClosure();
		close();
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean hasInitiatedClose()
	{
		return sslSocketBase.hasInitiatedClose();
	}
}