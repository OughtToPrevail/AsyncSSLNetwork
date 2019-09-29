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
package oughttoprevail.asyncsslnetwork.rw;

import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.Queue;

import oughttoprevail.asyncnetwork.Socket;
import oughttoprevail.asyncnetwork.pool.PooledByteBuffer;
import oughttoprevail.asyncnetwork.util.Predicate;
import oughttoprevail.asyncnetwork.util.reader.Reader;
import oughttoprevail.asyncsslnetwork.SSLSocket;
import oughttoprevail.asyncsslnetwork.SSLSocketBase;

/**
 * A reader {@link SSLSocket}.
 */
public class SSLReader extends Reader
{
	/**
	 * Queue of pending decrypted {@link ByteBuffer}
	 */
	private final Queue<ByteBuffer> pendingMessages;
	
	public SSLReader()
	{
		this.pendingMessages = new ArrayDeque<>();
	}
	
	
	/**
	 * Decrypts data in the socket's read byte buffer and invokes {@link Reader#callRequests(Socket, ByteBuffer)} with a
	 * decrypted temporary {@link PooledByteBuffer}.
	 *
	 * @param byteBuffer which contains input data
	 */
	@Override
	public void callRequests(Socket socket, ByteBuffer byteBuffer)
	{
		//We shall wait if handshake has yet to begin or we are handshaking but not waiting for data
		SSLSocketBase sslSocketBase = ((SSLSocket) socket).getSSLSocketBase();
		if(!sslSocketBase.hasHandshakeBegun() || (sslSocketBase.isHandshaking() && !sslSocketBase.isWaitingForUnwrap()))
		{
			return;
		}
		//need to decrypt byteBuffer
		byteBuffer.flip();
		try
		{
			while(byteBuffer.hasRemaining())
			{
				PooledByteBuffer decryptedByteBuffer = sslSocketBase.decrypt(byteBuffer);
				if(decryptedByteBuffer == null)
				{
					return;
				}
				ByteBuffer decrypted = decryptedByteBuffer.getByteBuffer();
				super.callRequests(socket, decrypted);
				if(decrypted.position() == 0)
				{
					decryptedByteBuffer.close();
				} else
				{
					pendingMessages.offer(decrypted);
				}
				if(sslSocketBase.getSSLEngine().isInboundDone())
				{
					return;
				}
			}
		} finally
		{
			byteBuffer.clear();
		}
	}
	
	/**
	 * An empty byte buffer to add requests if there is currently no decrypted data
	 */
	private static final ByteBuffer NULL_BYTE_BUFFER = ByteBuffer.allocate(0);
	
	/**
	 * Same as {@link Reader#addRequest(ByteBuffer, Predicate, int)} just the readBuffer is ignored and instead checks a queue to see if there are
	 * any unhandled buffers and if there are they're provided as the readBuffer, if there aren't then a {@link #NULL_BYTE_BUFFER} is.
	 *
	 * @param readBuffer ignored
	 * @param request read {@link Reader#addRequest(ByteBuffer, Predicate, int)}
	 * @param requestLength read {@link Reader#addRequest(ByteBuffer, Predicate, int)}
	 */
	@Override
	public void addRequest(ByteBuffer readBuffer, Predicate<ByteBuffer> request, int requestLength)
	{
		ByteBuffer decryptedByteBuffer = pendingMessages.peek();
		super.addRequest(decryptedByteBuffer == null ? NULL_BYTE_BUFFER : decryptedByteBuffer, request, requestLength);
		if(decryptedByteBuffer != null && decryptedByteBuffer.position() == 0)
		{
			pendingMessages.remove();
		}
	}
}