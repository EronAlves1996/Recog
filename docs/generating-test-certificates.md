```bash
# Generate a root CA key and self-signed certificate
openssl genrsa -out root-ca.key 4096
openssl req -x509 -new -nodes -key root-ca.key -sha256 -days 3650 -out ca.crt \
  -subj "/C=US/ST=California/L=San Francisco/O=Test CA/OU=Test Department/CN=Test Root CA"

# Generate a server key and certificate signing request
openssl genrsa -out server.key 2048
openssl req -new -sha256 -key server.key -out server.csr \
  -subj "/C=US/ST=California/L=San Francisco/O=Test Server/OU=Test Department/CN=localhost"

# Sign the server certificate with the root CA
openssl x509 -req -in server.csr -CA ca.crt -CAkey root-ca.key -CAcreateserial \
  -out server.crt -days 365 -sha256 -extfile <(echo -e "subjectAltName = DNS:localhost,IP:127.0.0.1")

# Create the certificate chain file for the client script
cp server.crt cmd/scripts/handshake/server-chain.pem
```
