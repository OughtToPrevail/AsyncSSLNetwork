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
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;

import oughttoprevail.asyncnetwork.Socket;
import oughttoprevail.asyncnetwork.pool.PooledByteBuffer;
import oughttoprevail.asyncnetwork.util.DisconnectionType;
import oughttoprevail.asyncnetwork.util.Validator;
import oughttoprevail.asyncsslnetwork.rw.SSLWriter;

/**
 * {@link SSLSocketBase} is the control for the SSL operations.
 */
public class SSLSocketBase implements SSLSocket
{
	/**
	 * The socket which requires SSL
	 */
	private final Socket socket;
	/**
	 * The {@link SSLWriter} of the {@link #socket}
	 */
	private final SSLWriter writer;
	/**
	 * The SSLContext used to create the {@link #sslEngine}
	 */
	private final SSLContext sslContext;
	/**
	 * The {@link SSLEngine} which will establish an SSL connection
	 */
	private final SSLEngine sslEngine;
	/**
	 * The {@link ExecutorService} which will be used when the {@link #sslEngine} requests to execute a task
	 */
	private final ExecutorService executor;
	/**
	 * Whether the handshake has begun
	 */
	private final AtomicBoolean handshakeBegun = new AtomicBoolean();
	/**
	 * Whether the handshake has completed
	 */
	private final AtomicBoolean handshakeCompleted = new AtomicBoolean();
	/**
	 * Whether the SSL has closed
	 */
	private final AtomicBoolean closed = new AtomicBoolean();
	/**
	 * Whether a handshake loop has temporarily stopped waiting for an unwrap
	 */
	private final AtomicBoolean waitingForUnwrap = new AtomicBoolean();
	/**
	 * The disconnectionType a {@link #closeSSL(DisconnectionType)} was invoked with
	 */
	private DisconnectionType disconnectionType;
	/**
	 * The {@link #readByteBuffer} lock to keep uses synchronous
	 */
	private final Object readByteBufferLock = new Object();
	/**
	 * A pooled object of the {@link #readByteBuffer}
	 */
	private PooledByteBuffer pooledReadByteBuffer;
	/**
	 * A {@link ByteBuffer} for reading operations (has encrypted input data)
	 */
	private ByteBuffer readByteBuffer;
	private int socketBufferRead;
	
	public SSLSocketBase(Socket socket, SSLWriter writer, SSLContext sslContext, boolean client, ExecutorService executor)
	{
		this.socket = socket;
		this.writer = writer;
		this.sslContext = sslContext;
		this.sslEngine = sslContext.createSSLEngine();
		sslEngine.setUseClientMode(client);
		this.executor = executor;
	}
	
	/**
	 * Begins the handshake process in which information will be transferred back and forth until
	 * a authentication and an agreed upon secret key have been established.
	 * Also sets {@link #hasHandshakeBegun()} to return true.
	 */
	@Override
	public void beginHandshake()
	{
		try
		{
			synchronized(handshakeCompleted)
			{
				handshakeCompleted.set(false);
			}
			synchronized(handshakeBegun)
			{
				handshakeBegun.set(true);
			}
			sslEngine.beginHandshake();
			createHandshakeLoop();
		} catch(SSLException e)
		{
			socket.manager().exception(e);
		}
	}
	
	/**
	 * Encrypts the specified writeByteBuffer into a temporary {@link PooledByteBuffer} with a {@link SSLEngine}
	 * wrap operation.
	 * Once finished with the returned {@link PooledByteBuffer} it should be closed.
	 *
	 * @param writeByteBuffer to encrypt
	 * @return a encrypted temporary {@link PooledByteBuffer}
	 */
	public PooledByteBuffer encrypt(ByteBuffer writeByteBuffer)
	{
		return wrap(writeByteBuffer);
	}
	
	public void fillReadByteBuffer(ByteBuffer input)
	{
		synchronized(readByteBufferLock)
		{
			if(socketBufferRead >= input.position())
			{
				input.clear();
				return;
			}
			initializeReadByteBuffer();
			input.flip();
			input.position(socketBufferRead);
			socketBufferRead = 0;
			input.limit(Math.min(readByteBuffer.capacity(), input.limit()));
			readByteBuffer.put(input);
			if(input.hasRemaining())
			{
				input.compact();
			} else
			{
				input.clear();
			}
		}
	}
	
	/**
	 * Decrypts the current readByteBuffer into a decrypted temporary {@link PooledByteBuffer} with
	 * a {@link SSLEngine} unwrap operation.
	 * Once finished with the returned the temporary {@link PooledByteBuffer} should be closed.
	 * To input data use {@link #fillReadByteBuffer(ByteBuffer)}
	 *
	 * @return a decrypted temporary {@link PooledByteBuffer}
	 */
	public PooledByteBuffer decrypt()
	{
		boolean handshakeUnwrap;
		synchronized(waitingForUnwrap)
		{
			handshakeUnwrap = waitingForUnwrap.compareAndSet(true, false);
		}
		synchronized(readByteBufferLock)
		{
			if(handshakeUnwrap)
			{
				if(!doHandshakeUnwrap())
				{
					return null;
				}
				createHandshakeLoop();
				synchronized(handshakeCompleted)
				{
					synchronized(readByteBufferLock)
					{
						if(!handshakeCompleted.get() || readByteBuffer.position() == 0)
						{
							return null;
						}
					}
				}
			}
			return unwrap();
		}
	}
	
	/**
	 * Returns whether the handshake is waiting for unwrap, meaning it is
	 * waiting for incoming data.
	 *
	 * @return whether the handshake is waiting for an unwrap
	 */
	public boolean isWaitingForUnwrap()
	{
		synchronized(waitingForUnwrap)
		{
			return waitingForUnwrap.get();
		}
	}
	
	/**
	 * Creates an handshake loop by continuously invoking {@link #continueHandshake()} as long
	 * as it returns {@code true}.
	 */
	private void createHandshakeLoop()
	{
		while(continueHandshake())
			;
	}
	
	/**
	 * Continues the handshake process.
	 * Returns {@code true} when the handshake process can gracefully continue
	 * and {@code false} when the handshake cannot continue without additional information
	 * or it has finished.
	 *
	 * @return whether the handshake process can gracefully continue
	 */
	private boolean continueHandshake()
	{
		HandshakeStatus status = sslEngine.getHandshakeStatus();
		//check whether the handshake has completed
		if(status == HandshakeStatus.FINISHED || status == HandshakeStatus.NOT_HANDSHAKING)
		{
			//if the handshake has already completed this is most likely a close finishing handshake
			waitingForUnwrap.set(false);
			if(handshakeCompleted.compareAndSet(false, true))
			{
				for(Runnable handshakeCompleteRunnable : onHandshakeComplete)
				{
					handshakeCompleteRunnable.run();
				}
			}
			return false;
		}
		//try to detect what the current handshake status is
		switch(status)
		{
			//if it is NEED_WRAP we need to send information to the end client
			case NEED_WRAP:
			{
				doHandshakeWrap();
				break;
			}
			
			//if it is NEED_UNWRAP we need to receive information from the end client
			case NEED_UNWRAP:
			{
				//try unwrap
				if(doHandshakeUnwrap())
				{
					break;
				}
				//set waitingForUnwrap to be true so when we receive a read we shouldn't ignore it
				waitingForUnwrapTrue();
				//return false since we need to wait until more information has arrived, until then the handshake cannot continue
				return false;
			}
			
			//if it is NEED_TASK we need to invoke it either in an executor or here depending whether an executor was provided in the constructor
			case NEED_TASK:
			{
				//loop through all tasks, once we take a task it is removed from the queue so this wont loop forever
				Runnable task;
				while((task = sslEngine.getDelegatedTask()) != null)
				{
					if(executor == null)
					{
						//if executor is null we need to execute it in the same thread
						task.run();
					} else
					{
						//if executor isn't null we should give the task to the executor to handle
						executor.execute(task);
					}
				}
				break;
			}
		}
		//return true since it seems that nothing has interrupted the process and it was finished successfully
		return true;
	}
	
	/**
	 * Writes an empty byteBufferElement to writer.
	 * This is useful since the {@link SSLWriter} uses {@link SSLEngine} when we give the {@link SSLEngine} an empty byteBufferElement during a handshake it ignores it
	 * then puts the information needed to be sent in the encrypted byteBuffer.
	 */
	private void doHandshakeWrap()
	{
		try(PooledByteBuffer byteBufferElement = new PooledByteBuffer(getPacketBufferSize()))
		{
			writer.encryptThenWrite(socket, byteBufferElement.getByteBuffer(), null);
		}
		//if both inbound and outbound is done then we can close the socket, this is after a "SSLSocketBaseImpl.createSSLEngineLoop(...)". so both
		//are probably already closed
		if(sslEngine.isOutboundDone() && sslEngine.isInboundDone())
		{
			//close socket, if disconnectionType is null which it usually is at this point it must mean we have received a close so it is a
			// REMOTE_CLOSE
			socket.manager().close(disconnectionType == null ? DisconnectionType.REMOTE_CLOSE : disconnectionType);
		}
	}
	
	/**
	 * Unwraps the specified readByteBuffer element then ignores the result letting {@link SSLEngine}
	 * handle the information we have decrypted (we don't need this information as it was sent by the engine if this is during a handshake).
	 *
	 * @return whether a decryption occurred
	 */
	private boolean doHandshakeUnwrap()
	{
		initializeReadByteBuffer();
		PooledByteBuffer decrypted = unwrap();
		if(decrypted != null)
		{
			decrypted.close();
		}
		/*synchronized(readByteBufferLock)
		{
			//if any information is left we should be putting it at the start of readByteBuffer for next time
			readByteBuffer.compact();
		}*/
		return decrypted != null;
	}
	
	/**
	 * Initializes the read byte buffer
	 */
	private void initializeReadByteBuffer()
	{
		synchronized(readByteBufferLock)
		{
			if(this.readByteBuffer == null)
			{
				pooledReadByteBuffer = new PooledByteBuffer(sslEngine.getSession().getPacketBufferSize());
				readByteBuffer = pooledReadByteBuffer.getByteBuffer();
			}
		}
	}
	
	/**
	 * Wraps the specified writeByteBuffer.
	 *
	 * @param writeByteBuffer to wrap
	 * @return a wrapped (encrypted) byteBuffer, the encrypted byteBuffer should
	 * be closed after it has finished writing
	 */
	private PooledByteBuffer wrap(ByteBuffer writeByteBuffer)
	{
		return createSSLResultLoop(writeByteBuffer, true);
	}
	
	/**
	 * Unwraps the specified readByteBuffer.
	 *
	 * @return a unwrapped (decrypted) byteBuffer,
	 * the decrypted byteBuffer should be closed after it has been dealt with
	 */
	private PooledByteBuffer unwrap()
	{
		synchronized(readByteBufferLock)
		{
			ByteBuffer byteBuffer = socket.manager().getReadByteBuffer().getByteBuffer();
			int limit = byteBuffer.limit();
			if(socketBufferRead < limit)
			{
				int position = byteBuffer.position();
				byteBuffer.position(socketBufferRead);
				int written;
				byteBuffer.limit(written = Math.min(position - socketBufferRead, readByteBuffer.capacity() - readByteBuffer.position()));
				socketBufferRead+=written;
				readByteBuffer.put(byteBuffer);
				byteBuffer.limit(limit);
				byteBuffer.position(position);
			}
			
			readByteBuffer.flip();
			PooledByteBuffer pooledByteBuffer = createSSLResultLoop(readByteBuffer, false);
			if(readByteBuffer.position() > 0)
			{
				readByteBuffer.compact();
			} else
			{
				readByteBuffer.position(readByteBuffer.limit());
				readByteBuffer.limit(readByteBuffer.capacity());
			}
			return pooledByteBuffer;
		}
	}
	
	/**
	 * Creates a loop which will try to wrap/unwrap depending on the specified wrap
	 * until the {@link SSLEngineResult} was {@link javax.net.ssl.SSLEngineResult.Status#OK} or
	 * {@link SSLEngineResult.Status#CLOSED}.
	 * If the specified wrap is {@code true} then {@link SSLEngine#wrap(ByteBuffer, ByteBuffer)} is invoked
	 * else {@link SSLEngine#unwrap(ByteBuffer, ByteBuffer)} is invoked.
	 *
	 * @param src is the source byteBuffer which is in need of either wrap/unwrap depending on the specified wrap
	 * @param wrap is whether {@link SSLEngine#wrap(ByteBuffer, ByteBuffer)} should be invoked or
	 * {@link SSLEngine#unwrap(ByteBuffer, ByteBuffer)} should be invoked
	 * @return {@code null} if either an exception or {@link SSLEngineResult.Status#CLOSED} is returned
	 * from wrap/unwrap else the dst (destination buffer) is returned
	 */
	private PooledByteBuffer createSSLResultLoop(ByteBuffer src, boolean wrap)
	{
		/*
		the dstSize (destination size) should be for a wrap operation the packet buffer size and for a
		unwrap operation the application buffer size.
		This is because if we are wrapping (encrypting) then we need a packet buffer size which is the size of the encrypted packet
		and if we're unwrapping (decrypting) then we need a application buffer size which is the size of the decrypted packet
		 */
		int dstSize = wrap ? getPacketBufferSize() : getApplicationBufferSize();
		//Take a byteBuffer which the result will go to, this is called the destination (dst)
		PooledByteBuffer dst = new PooledByteBuffer(dstSize);
		try
		{
			//keep a variable to know whether this is the first loop, we will need this later
			engineLoop:
			while(true)
			{
				//take the values before the while loop so if they were changed last loop the byteBuffers will also be different
				ByteBuffer dstByteBuffer = dst.getByteBuffer();
				//get the engineResult by invoking sslEngine.wrap or sslEngine.unwrap depending on the specified wrap and put the srcByteBuffer and
				// dstByteBuffer as the parameters
				SSLEngineResult engineResult = wrap ? sslEngine.wrap(src, dstByteBuffer) : sslEngine.unwrap(src, dstByteBuffer);
				//try to find the status
				switch(engineResult.getStatus())
				{
					//If it is OK then we're good it means the operation has completed successfully and we can continue
					case OK:
					{
						//The SSLEngine completed the operation, and is available to process similar calls.
						break engineLoop;
					}
					
					//If it is BUFFER_OVERFLOW then we need to expand the current destination buffer (dst)
					case BUFFER_OVERFLOW:
					{
						//The SSLEngine was not able to process the operation because there are not enough bytes available in the destination buffer
						// to hold the result.
						dst = expand(dstSize + dstByteBuffer.position(), dstByteBuffer, dst, false);
						break;
					}
					
					/*
					If it is BUFFER_UNDERFLOW then we need to check whether this is because there isn't enough space for
					a complete packet or because there isn't enough data in the packet.
					If there isn't enough space we need to expand the current source buffer (src).
					Then we need to wait for more data and return null since we couldn't get a full result
					 */
					case BUFFER_UNDERFLOW:
					{
						if(wrap)
						{
							throw new IllegalArgumentException("SSLEngineResult.BUFFER_UNDERFLOW should not occur on wrap!");
						}
						//The SSLEngine was not able to unwrap the incoming data because there were not enough source bytes available to make a
						// complete packet.
						int packetBufferSize = getPacketBufferSize();
						if(src.capacity() < packetBufferSize)
						{
							synchronized(readByteBufferLock)
							{
								//expand the src
								PooledByteBuffer newSrc = expand(packetBufferSize, src, pooledReadByteBuffer, true);
								//set the socket read byteBuffer to the new src since the old one didn't have enough space for the a packet
								this.pooledReadByteBuffer = newSrc;
								this.readByteBuffer = newSrc.getByteBuffer();
							}
						}
						//not enough data in buffer
						waitingForUnwrapTrue();
						dst.close();
						return null;
					}
					//If it is CLOSED we need to close the engine
					case CLOSED:
					{
						//The operation just closed this side of the SSLEngine, or the operation could not be completed because it was already
						// closed.
						//set closed to true, this useful encase this is unwrap and it didn't go through "SSLSocketBaseImpl.closeSSL()"
						synchronized(closed)
						{
							closed.set(true);
						}
						//outbound is what we will send (wrap), if outbound is done this means we don't have anymore to send
						//if outbound is done then we need to close it, if it was already closed this operation will do nothing
						boolean outboundDone;
						if(outboundDone = sslEngine.isOutboundDone())
						{
							//close outbound
							sslEngine.closeOutbound();
						}
						//inbound is what we will receive (unwrap), if inbound is done this means we don't have anything expected to read
						//if inbound is done then we need to close it, if it was already closed this operation will do nothing
						if(sslEngine.isInboundDone())
						{
							//close inbound
							sslEngine.closeInbound();
							//if inbound and outbound are done it means that SSL has finished it's close and we can finally close (disconnect)
							if(outboundDone)
							{
								//if this isn't a wrap operation close the socket, if it is a wrap operation a write must occur so we can't close
								// the socket now
								if(!wrap)
								{
									//close socket
									socket.manager().close(disconnectionType);
								}
							} else
							{
								//create a handshake loop so a closing handshake can begin
								createHandshakeLoop();
							}
						}
						break engineLoop;
					}
				}
			}
			return dst;
		} catch(SSLException e)
		{
			//an exception occurred, leave the destination buffer and give the exception to the socket
			dst.close();
			socket.manager().exception(e);
			//return null since we don't have a destination buffer anymore
			return null;
		}
	}
	
	/**
	 * Sets {@link #waitingForUnwrap} to {@code true} if there is still a handshake
	 */
	private void waitingForUnwrapTrue()
	{
		if(isHandshaking())
		{
			synchronized(waitingForUnwrap)
			{
				waitingForUnwrap.set(true);
			}
		}
	}
	
	/**
	 * Expands the specified currentByteBuffer into the specified newSize.
	 * If the specified addContents is {@code true} then the specified currentByteBuffer
	 * contents are added into the new expanded byteBuffer.
	 *
	 * @param newSize is the size the new expanded byteBuffer should be
	 * @param currentByteBuffer is the current byteBuffer
	 * @param addContents is whether the contents of the specified currentByteBuffer should be
	 * put into the new expanded byteBuffer
	 * @param pooledByteBuffer is the {@link PooledByteBuffer} of the specified currentByteBuffer
	 * or if it isn't a {@link PooledByteBuffer} then {@code null}
	 * @return an expanded byteBuffer
	 */
	private PooledByteBuffer expand(int newSize, ByteBuffer currentByteBuffer, PooledByteBuffer pooledByteBuffer, boolean addContents)
	{
		PooledByteBuffer expandedByteBuffer = new PooledByteBuffer(newSize);
		if(addContents)
		{
			currentByteBuffer.position(0);
			expandedByteBuffer.getByteBuffer().put(currentByteBuffer);
		}
		pooledByteBuffer.close();
		return expandedByteBuffer;
	}
	
	/**
	 * Returns the applicationBufferSize of the current session.
	 * The applicationBufferSize determines the max size of a plaintext packet
	 *
	 * @return the applicationBufferSize of the current session
	 */
	private int getApplicationBufferSize()
	{
		return sslEngine.getSession().getApplicationBufferSize();
	}
	
	/**
	 * Returns the packetBufferSize of the current session.
	 * The packetBufferSize determines the max size of a ciphertext packet
	 *
	 * @return the packetBufferSize of the current session
	 */
	private int getPacketBufferSize()
	{
		return sslEngine.getSession().getPacketBufferSize();
	}
	
	/**
	 * List of runnables to be executed when an handshake is complete
	 */
	private final List<Runnable> onHandshakeComplete = new ArrayList<>();
	
	/**
	 * Invokes the specified onHandshakeComplete once the handshake process has successfully
	 * completed.
	 *
	 * @param onHandshakeComplete to invoke once the handshake process has successfully complete
	 */
	@Override
	public void onHandshakeComplete(Runnable onHandshakeComplete)
	{
		if(isHandshakeComplete())
		{
			Validator.runRunnable(onHandshakeComplete);
		} else
		{
			this.onHandshakeComplete.add(onHandshakeComplete);
		}
	}
	
	/**
	 * Returns whether the handshake process has begun.
	 * To begin the handshake process invoke {@link #beginHandshake()}.
	 *
	 * @return whether the handshake process has begun.
	 */
	@Override
	public boolean hasHandshakeBegun()
	{
		synchronized(handshakeBegun)
		{
			return handshakeBegun.get();
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean isHandshakeComplete()
	{
		synchronized(handshakeCompleted)
		{
			return handshakeCompleted.get();
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public SSLEngine getSSLEngine()
	{
		return sslEngine;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public SSLContext getSSLContext()
	{
		return sslContext;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public SSLSocketBase getSSLSocketBase()
	{
		return this;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void forceClosure()
	{
		synchronized(closed)
		{
			closed.set(true);
		}
		sslEngine.closeOutbound();
		try
		{
			sslEngine.closeInbound();
		} catch(SSLException e)
		{
			socket.manager().exception(e);
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean hasInitiatedClose()
	{
		synchronized(closed)
		{
			return closed.get();
		}
	}
	
	/**
	 * Closes the SSL process with a close handshake.
	 *
	 * @param disconnectionType is the reason the {@link Socket} is requesting a close
	 * @return {@code true} if the {@link Socket} should close without a SSL close handshake,
	 * else {@code false}
	 */
	boolean closeSSL(DisconnectionType disconnectionType)
	{
		//if already closed then return true
		if(hasInitiatedClose())
		{
			return true;
		}
		//if it was closed by a remote close then we can't continue
		if(disconnectionType == DisconnectionType.REMOTE_CLOSE_BY_EXCEPTION || disconnectionType == DisconnectionType.REMOTE_CLOSE)
		{
			//force close
			forceClosure();
			//return true since we can't do anything about this
			return true;
		}
		//set closed to true
		closed.set(true);
		//set disconnectionType to the specified disconnectionType so when we actually close the socket we can pass it on
		this.disconnectionType = disconnectionType;
		//notify the SSLEngine we are closing by closing the outbound
		sslEngine.closeOutbound();
		//create a handshake loop to initiate the close handshake
		createHandshakeLoop();
		//return false since the the socket shouldn't close just yet, the handshake loop will close the socket once it's finished
		return false;
	}
}