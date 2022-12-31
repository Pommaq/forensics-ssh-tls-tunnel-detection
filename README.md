
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
