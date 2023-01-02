
# Getting started:

## TLS tunnel:
Generate new certificates for the TLS tunnel by calling
```
openssl req -new -x509 -days 365 -nodes -out ./clientside/stunnel.pem -keyout ./clientside/stunnel.pem
openssl req -new -x509 -days 365 -nodes -out ./serverside/stunnel.pem -keyout ./serverside/stunnel.pem
```

then run the following to start the tunnel over localhost.
```
python ./tls_tunnel/main.py 
```
or call clientside.py and serverside.py manually.


To configure the client to connect to the proxy, 
ensure clientside.target_port and clientside.target match  serverside.source_port and serverside.source


Configure the target by setting serverside.target and serverside.target_port towards wherever the client wishes to connect towards.

The tunnel must begin from clientside towards serverside before two-way communication can start.


## TLS parser
Ensure tls-tunneled training data (i.e. data confirmed to be tunneled SSH handshakes) is stored in 
```
./training.pcapng
```
and the data to be scanned is located in 
```
./testdata.pcapng
```

additionally make sure to set the server_port arguments inside fn main() to their correct values.
i.e. if one wishes to scan for SSH over HTTPS, make sure the call for perform_analysis looks similar to
```rust
fn main() {
    let trainingfile = File::open("./training.pcapng").unwrap();
    let rules = generate_rules(trainingfile, 443);

    let truefile = File::open("./testdata.pcapng").unwrap();
    perform_analysis(truefile, &rules, 443);
}

```


# Caveats
## TLS tunnel
It only permits one connection at a time, if the client disconnects from the clientside, the server won't break the connection
and will additionally continue using the previous connection for any succeeding clients.

## TLS parser
Lots. It's a buggy mess, but I didnt bother fixing most since it did its task
just fine assuming good network conditions (it doesnt handle out-of-order packets nor retransmissions well at all).
The final rule (3rd) may be buggy and allow any size, I wont bother investigating this due to, once again, time constraints and it
working fine enough to not result in false positives nor false negatives during testing.

Timing-based checks are broken due to timestamps being negative for some stupid reason. I decided to simply 
disable it for now.
