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

import oughttoprevail.asyncnetwork.Socket;
import oughttoprevail.asyncnetwork.util.Consumer;

/**
 * A {@link SSLSocket} contain the functions required to support SSL.
 */
public interface SSLSocket
{
	/**
	 * Begins the handshake process in which information will be transferred back and forth until
	 * a authentication and an agreed upon secret key have been established.
	 * Also sets {@link #hasHandshakeBegun()} to return true.
	 */
	void beginHandshake();
	
	/**
	 * Invokes the specified onHandshakeComplete once the handshake process has successfully
	 * completed.
	 *
	 * @param onHandshakeComplete to invoke once the handshake process has successfully complete
	 */
	void onHandshakeComplete(Runnable onHandshakeComplete);
	
	/**
	 * Returns whether the handshake process has begun.
	 * To begin the handshake process invoke {@link #beginHandshake()}.
	 *
	 * @return whether the handshake process has begun.
	 */
	boolean hasHandshakeBegun();
	
	/**
	 * Returns whether the handshake process has complete.
	 * If you want to be notified when this will return {@code true}
	 * invoke {@link #onHandshakeComplete(Runnable)}.
	 *
	 * @return whether the handshake process has complete
	 */
	boolean isHandshakeComplete();
	
	/**
	 * @return whether a handshake is currently running
	 */
	default boolean isHandshaking()
	{
		return hasHandshakeBegun() && !isHandshakeComplete();
	}
	
	/**
	 * @return the socket's {@link SSLEngine}
	 */
	SSLEngine getSSLEngine();
	
	/**
	 * @return the {@link SSLContext} which created the socket's {@link SSLEngine}
	 */
	SSLContext getSSLContext();
	
	/**
	 * @return the {@link SSLSocketBase} of this
	 */
	SSLSocketBase getSSLSocketBase();
	
	/**
	 * Forces the {@link Socket} to close.
	 *
	 * If the socket has yet to be closed.
	 * The {@link SocketChannel} will be closed and the onDisconnect
	 * that is specified by {@link Socket#onDisconnect(Consumer)} will be invoked.
	 */
	void forceClosure();
	
	/**
	 * @return whether the socket has initiated a close
	 */
	boolean hasInitiatedClose();
}