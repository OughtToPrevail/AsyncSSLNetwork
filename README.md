# AsyncSSLNetwork
*AsyncSSLNetwork* short for Asynchronous Secure Socket Layer Network is a library which implements the AsyncNetwork
library with the additional feature of SSL sockets.

## Features
* Cross platform
* Asynchronous
* Uses Java's SSLEngine
* Easy-to-use

## Maven
```xml

```

## How to use
To create a client you would:
```java
SSLClientSocket socket = new SSLClientSocket(SSLContextFactory.createContext("Client.jks", "Client Password".toCharArray()));
socket.connect(new InetSocketAddress("localhost", 6000));
socket.onConnect(() ->
{
	System.out.println("Established connection");
	socket.getSSLEngine().setEnabledCipherSuites(socket.getSSLEngine().getSupportedCipherSuites());
	socket.onHandshakeComplete(() ->
	{
		System.out.println("Handshake successful");
		WritablePacketBuilder.create().putString("Hello? are you there?").build().writeAndClose(socket);
		ReadablePacketBuilder.create(true).aString().build().read(socket, readResult -> System.out.println("Read " + readResult.poll()));
		socket.onDisconnect(disconnectionType -> System.out.println("Disconnected: " + disconnectionType));
	});
	socket.beginHandshake();
});
```
Note: you don't have to use SSLContextFactory, if you have your own SSLContext, you can use it
```java
SSLServerSocket serverSocket = new SSLServerSocket(SSLContextFactory.createContext("Server.jks", "Hello World!".toCharArray()));
serverSocket.onSSLConnection(socket ->
{
	System.out.println("Established connection");
	socket.onException(Throwable::printStackTrace);
	SSLEngine sslEngine = socket.getSSLEngine();
	sslEngine.setEnabledCipherSuites(new String[]{"TLS_ECDH_anon_WITH_AES_256_CBC_SHA"});
	socket.onHandshakeComplete(() ->
	{
		System.out.println("Handshake successful");
		ReadablePacketBuilder.create(true).aString().build().read(socket, readResult -> System.out.println((String) readResult.poll()));
		WritablePacketBuilder.create().putString("Hello there! How are you today?").build().writeAndClose(socket);
		socket.onDisconnect(disconnectionType -> System.out.println("Disconnected: " + disconnectionType));
	});
	socket.beginHandshake();
});
serverSocket.bindLocalHost(6000);
while(true);
```
Note: I am using "anon" in my cipher suite because I am not using a certificate in my TrustManager, you should not be
using it, also, SSLContextFactory is not a class in the project, it's only in test\java directory, to create a simple
SSLContext, it should only be used for testing, for actual production you should use an SSLContext with certificates,
proper keystores and truststores and with your own attributes.

And you're finished! Now you can use AsyncSSLNetwork to protect your networks.