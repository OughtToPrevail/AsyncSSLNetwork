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

import oughttoprevail.asyncnetwork.packet.read.ReadablePacketBuilder;
import oughttoprevail.asyncnetwork.packet.write.WritablePacketBuilder;
import oughttoprevail.asyncsslnetwork.SSLClientSocket;

public class SSLTest
{
	public static void main(String[] args) throws Exception
	{
		new SSLTest();
	}
	
	private SSLTest() throws Exception
	{
		SSLClientSocket socket = new SSLClientSocket(SSLContextFactory.createContext("Client.jks", "Client Password".toCharArray()));
		socket.onConnect(() ->
		{
			System.out.println("Established connection");
			socket.getSSLEngine().setEnabledCipherSuites(socket.getSSLEngine().getSupportedCipherSuites());
			socket.onHandshakeComplete(() ->
			{
				System.out.println("Handshake successful");
				WritablePacketBuilder.create().putString("Hello? are you there?").build().writeAndClose(socket);
				ReadablePacketBuilder.create().aString().build().read(socket, readResult -> System.out.println((String) readResult.poll()));
				socket.onDisconnect(disconnectionType -> System.out.println("DISCONNECTIONTYPE " + disconnectionType));
			});
			socket.beginHandshake();
		});
		socket.connectLocalHost(6000);
	}
}