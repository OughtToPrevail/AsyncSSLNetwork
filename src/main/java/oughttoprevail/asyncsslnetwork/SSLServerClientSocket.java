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
import java.nio.channels.SocketChannel;
import java.util.concurrent.Executors;

import oughttoprevail.asyncnetwork.server.ServerClientSocket;
import oughttoprevail.asyncnetwork.util.DisconnectionType;
import oughttoprevail.asyncnetwork.util.writer.server.ServerWriter;
import oughttoprevail.asyncnetwork.util.writer.server.WindowsWriter;
import oughttoprevail.asyncsslnetwork.rw.SSLReader;
import oughttoprevail.asyncsslnetwork.rw.SSLWriter;

/**
 * An {@link SSLServerClientSocket} is a {@link ServerClientSocket} which handles SSL for both reading writing.
 */
public class SSLServerClientSocket extends ServerClientSocket implements SSLSocket
{
	/**
	 * The {@link SSLSocketBase} is the SSL controller of this socket,
	 * it will handle all the SSL related tasks.
	 */
	private SSLSocketBase sslSocketBase;
	
	public SSLServerClientSocket(SSLServerSocket server, SocketChannel socketChannel, int clientsIndex)
	{
		this(server, socketChannel, clientsIndex, new SSLWriter(server.manager().isWindowsImplementation() ? new WindowsWriter() : new ServerWriter()), new SSLReader());
	}
	
	private SSLServerClientSocket(SSLServerSocket server, SocketChannel socketChannel, int clientsIndex, SSLWriter writer, SSLReader reader)
	{
		super(server, socketChannel, clientsIndex, reader, writer);
		sslSocketBase = new SSLSocketBase(this, writer, server.getSSLContext(), false, Executors.newFixedThreadPool((int) Math.ceil(server.getThreadsCount() / 5d), r -> new Thread(r, "SSL Tasks Thread")));
		reader.init(sslSocketBase);
		
	}
	
	/**
	 * Whether the closure will be forced or initiate a SSL sequence
	 */
	private boolean forceClosure;
	
	/**
	 * Invoked before the closed has occurred, this is useful for extending classes to make final changes.
	 *
	 * @param disconnectionType is the reason why the disconnection should occur
	 * @return whether the close should continue, if {@code true} the close will continue if
	 * {@code false} the close will stop
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
			super.preClose(disconnectionType);
			return true;
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
	@Override
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
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public SSLSocketBase getSSLSocketBase()
	{
		return sslSocketBase;
	}
}