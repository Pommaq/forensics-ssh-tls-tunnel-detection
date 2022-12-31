import generic
import ssl
import asyncio

target = "127.0.0.1"
target_port = 8889  # 443

source = "127.0.0.1"
source_port = 8888


async def server_cb(reader, writer):
    print("Got connection, opening towards target")
    tar_reader, tar_writer = await asyncio.open_connection(target, target_port)
    loop = asyncio.get_event_loop()

    transport = tar_writer.transport
    proto = transport.get_protocol()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain("./clientside/stunnel.pem")

    new_transport = await loop.start_tls(transport, proto, context, server_side=False)
    tar_writer._transport = new_transport
    tar_reader._transport = new_transport

    await asyncio.gather(
        generic.towards_server(reader, tar_writer),
        generic.from_server(writer, tar_reader),
    )
    tar_writer.close()


async def main():
    # Wait until we receive a connection
    server = await asyncio.start_server(
        client_connected_cb=server_cb, host=source, port=source_port, reuse_address=True
    )
    async with server:
        await server.serve_forever()
