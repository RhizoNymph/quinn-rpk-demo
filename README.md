# quinn-rpk-demo

This is a basic demo of how to set up a QUIC connection that uses [IETF RFC 7250](https://datatracker.ietf.org/doc/html/rfc7250) for Raw Public Key authentication. This is useful for peer to peer networks where you don't need to validate against certs against a certificate authority or where trusted self signed certificates are distributed with each part of a system.

The demo supports ED25519 keypairs and validates on both sides that the message is signed by the public key that represents the peer identity.

## Instructions

To run the server:
```
cargo run server
```
it also supports a listen address if you want to run this not on the same computer as the client (it defaults to 127.0.0.1:4433):
```
cargo run server --listen 0.0.0.0:4433
```

To run the client:
```
cargo run client
```
it also supports a server address if you want to run this not on the same computer as the server:
```
cargo run client --server <SERVER_IP>
```

both of these support:
```
--key <PATH> --cert <PATH>
```
## Code Overview

### Common
The client and server implementations share a common make_rpk function that takes in options for the key path and cert path if files exist at these paths. If these arguments aren't passed in, it will generate new keypairs for server or client depending on the caller of the function (make_rpk accepts default key and cert path which are set by client and server when calling). 

Key generation is handled with rcgen through KeyPair and PKCS_ED25519. Key saving is handled using the .serialize_der() fn on the KeyPair struct. Key loading is handled with:
- rustls::pki_types{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer} 
- rustls::sign::{CertifiedKey, SigningKey}
- crypto::ring::sign::any_eddsa_type

### Server
To handle RPK we need to implement our own ClientCertVerifier trait for our client struct and pass it to the .with_client_cert_verifier mutator fn on ServerConfig::builder() as well as the ResolvesServerCert trait for a OneRpk struct that resolves the first cert sent and pass this into the .with_cert_resolver mutator fn on the config builder. The output of this can be used to build the QuicServerConfig with try_from() and the ServerConfig using with_crypto() and finally the Endpoint using server(). After these we can spawn the accept loop which connects to clients and prints the peer ID public key that is connecting before echoing the client data back to them.

### Client
Similarly to the server, for the client we need to implement a ServerCertVerifier trait for the client struct and pass it to the .with_server_cert_verifier() mutator fn on the ClientConfig::builder() along with a OneRpk struct that implements ResolvesClientCert and pass this to the .with_cert_resolver() mutator fn. This then allows us to build the endpoint through the QuicClientConfig::try_from() being passed into the ClientConfig::new() and finally Endpoint::client. After this we can connect to server_addr with the endpoints connect() fn and get the peer identity of the server and verify it before sending data which gets echoed back to the client.