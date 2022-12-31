import asyncio


async def towards_server(client: asyncio.StreamReader, writer: asyncio.StreamWriter):
    while True:
        data = await client.read(4096)
        writer.write(data)
        await writer.drain()


async def from_server(client: asyncio.StreamWriter, reader: asyncio.StreamReader):
    while True:
        data = await reader.read(4096)
        client.write(data)
        await client.drain()
