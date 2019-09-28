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
import java.net.SocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;

import oughttoprevail.asyncnetwork.server.ServerClientSocket;
import oughttoprevail.asyncnetwork.server.ServerSocket;
import oughttoprevail.asyncnetwork.util.Consumer;
import oughttoprevail.asyncnetwork.util.SelectorImplementation;

/**
 * A {@link SSLServerSocket} is a {@link ServerSocket} which creates {@link SSLServerClientSocket} to support SSL operations.
 */
public class SSLServerSocket extends ServerSocket
{
	/**
	 * The {@link SSLContext} which will create all {@link javax.net.ssl.SSLEngine}'s.
	 */
	private final SSLContext sslContext;
	
	public SSLServerSocket(SSLContext sslContext)
	{
		this.sslContext = sslContext;
	}
	
	public SSLServerSocket(int bufferSize,
						   int selectTimeout,
						   int selectArraySize,
						   int threadsCount,
						   SelectorImplementation implementation,
						   SSLContext sslContext)
	{
		super(bufferSize, selectTimeout, selectArraySize, threadsCount, implementation);
		this.sslContext = sslContext;
	}
	
	/**
	 * invokes the specified consumer when a client has connected.
	 *
	 * @param onConnection the consumer that will be called when a client connects
	 */
	public void onSSLConnection(Consumer<SSLServerClientSocket> onConnection)
	{
		onConnection(serverClientSocket -> onConnection.accept((SSLServerClientSocket) serverClientSocket));
	}
	
	/**
	 * Invokes {@link ServerSocketChannel#bind(SocketAddress, int)} with the specified address and
	 * specified backlog.
	 *
	 * @param address the address that will be used when calling {@link
	 * ServerSocketChannel#bind(SocketAddress, int)}
	 * @param backlog maximum rate the server can accept new TCP connections on a socket
	 * if 0 Java will use it's default
	 */
	@Override
	public void bind(SocketAddress address, int backlog)
	{
		super.bind(address, backlog);
	}
	
	/**
	 * @return the server's {@link SSLContext}
	 */
	public SSLContext getSSLContext()
	{
		return sslContext;
	}
	
	@Override
	protected ServerClientSocket createServerClientSocket(SocketChannel socketChannel, int clientsIndex)
	{
		return new SSLServerClientSocket(this, socketChannel, clientsIndex);
	}
}