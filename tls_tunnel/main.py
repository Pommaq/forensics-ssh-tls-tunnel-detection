import asyncio

import clientside
import endpoint


async def main():
    await asyncio.gather(clientside.main(), endpoint.main())


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
