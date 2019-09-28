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

import javax.net.ssl.SSLEngine;

import oughttoprevail.asyncnetwork.packet.ReadablePacketBuilder;
import oughttoprevail.asyncnetwork.packet.WritablePacketBuilder;
import oughttoprevail.asyncsslnetwork.SSLServerSocket;

public class SSLServerTest
{
	public static void main(String[] args) throws Exception
	{
	    new SSLServerTest();
	}
	
	private SSLServerTest() throws Exception
	{
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
				socket.onDisconnect(disconnectionType -> System.out.println("DISCONNECTIONTYPE " + disconnectionType));
			});
			socket.beginHandshake();
		});
		serverSocket.bindLocalHost(6000);
		while(true);
	}
}