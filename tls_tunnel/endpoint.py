import ssl
import asyncio

import generic

target = "ssh.example.com"
target_port = 22

source = "127.0.0.1"
source_port = 8889  # 443


async def server_cb(reader, writer):

    # Start connection towards target
    print("Got connection, opening towards target")
    tar_reader, tar_writer = await asyncio.open_connection(target, target_port)
    await asyncio.gather(
        generic.towards_server(reader, tar_writer),
        generic.from_server(writer, tar_reader),
    )
    tar_writer.close()


async def serve():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain("./serverside/stunnel.pem")

    server = await asyncio.start_server(
        client_connected_cb=server_cb,
        host=source,
        port=source_port,
        ssl=ctx,
        reuse_address=True,
    )
    async with server:
        await server.serve_forever()


async def main():
    # Wait until we receive a connection
    await serve()


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
