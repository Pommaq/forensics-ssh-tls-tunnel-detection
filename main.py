import socket
import ssl
import asyncio

target = "127.0.0.1"
target_port = 8889 # 443

source = "127.0.0.1"
source_port = 8888


async def towards_server(client: socket.socket, writer: asyncio.StreamWriter):
    while True:
        loop = asyncio.get_event_loop()
        data = await loop.sock_recv(client, 4096)

        writer.write(data)
        await writer.drain()


async def from_server(client: socket.socket, reader: asyncio.StreamReader):
    while True:
        data = await reader.read(4096)

        loop = asyncio.get_event_loop()
        await loop.sock_sendall(client, data)


async def main():
    # Wait until we receive a connection
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((source, source_port))
    server.listen()
    server.setblocking(False)
    loop = asyncio.get_event_loop()

    client, aaaaaa = await loop.sock_accept(server)

    # Start connection towards target
    reader, writer = await asyncio.open_connection(target, target_port)
    transport = writer.transport
    proto = transport.get_protocol()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain("./clientside/stunnel.pem")

    context.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384')

    new_transport = await loop.start_tls(transport, proto, context, server_side=False)
    writer._transport = new_transport
    reader._transport = new_transport

    await asyncio.gather(towards_server(client, writer), from_server(client, reader))


if __name__ == "__main__":
    asyncio.run(main())

"""
METHODS:
    We can measure expected sizes of packages during handshakes. Then listen for them. 
    
    This can probably be applied for HTTP, by measuring differences between packet sizes.
    
    Certain sizes will vary depending on keys used, supported etc. 
    
    SSH handshake is 7 packets.
    client -> server
    
    HELLO ->
    HELLO <-
    KEY EXCHANGE INIT ->
    KEY EXCHANGE INIT <-
    (if found supported methods)
    <method> EXCHANGE INIT ->
    <method> EXCHANGE INIT <-
    NEW KEYS -> 
    
    

    
    
"""
