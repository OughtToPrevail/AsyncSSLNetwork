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

import oughttoprevail.asyncnetwork.Socket;
import oughttoprevail.asyncnetwork.pool.PooledByteBuffer;
import oughttoprevail.asyncnetwork.util.Consumer;
import oughttoprevail.asyncnetwork.util.writer.Writer;
import oughttoprevail.asyncsslnetwork.SSLSocket;

/**
 * A writer for {@link SSLSocket}.
 */
public class SSLWriter implements Writer
{
	/**
	 * The writer that actually writes to the socket
	 */
	private final Writer writer;
	
	public SSLWriter(Writer writer)
	{
		this.writer = writer;
	}
	
	/**
	 * Encrypts the specified writeBuffer then writes the encrypted buffer.
	 * Once finished, the specified onWriteFinished will be invoked.
	 *
	 * @param socket to write to
	 * @param writeBuffer to encrypt
	 * @param onWriteFinished to invoke when finished (possibly {@code null})
	 */
	public void encryptThenWrite(Socket socket, ByteBuffer writeBuffer, Consumer<ByteBuffer> onWriteFinished)
	{
		System.out.println("Write " + socket.isClosed());
		PooledByteBuffer encryptedByteBufferElement = ((SSLSocket) socket).getSSLSocketBase().encrypt(writeBuffer);
		ByteBuffer encryptedByteBuffer = encryptedByteBufferElement.getByteBuffer();
		encryptedByteBuffer.flip();
		System.out.println("Write encrypted " + encryptedByteBuffer + " " + socket.getSocketChannel().isOpen());
		writer.write(socket, encryptedByteBuffer, byteBuffer ->
		{
			System.out.println("Finished write");
			encryptedByteBufferElement.close();
			if(onWriteFinished != null)
			{
				onWriteFinished.accept(byteBuffer);
			}
		});
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void write(Socket socket, ByteBuffer writeBuffer, Consumer<ByteBuffer> onWriteFinished)
	{
		if(!((SSLSocket) socket).isHandshakeComplete())
		{
			throw new IllegalStateException("You cannot write until handshake is complete!");
		}
		encryptThenWrite(socket, writeBuffer, onWriteFinished);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean continueWriting()
	{
		return writer.continueWriting();
	}
}