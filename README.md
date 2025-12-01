# Recog

A Go-based playground for security and cryptography concepts.

## Overview

Recog is a service designed to experiment with and demonstrate various security and cryptographic primitives. It provides a simple RESTful API to interact with concepts like hashing, digital signatures, secure key exchange, session management, and certificate validation. The project is built with Go and the Gin web framework, and it's intended to evolve, incorporating more security experiments as it grows.

## Features

- Calculate SHA256 hash of uploaded files.
- Sign and verify text messages with an RSA key pair.
- Perform an ECDH key exchange for secure session establishment.
- Session ticket management for efficient session resumption.
- X.509 certificate validation with OCSP revocation checking, signature algorithm verification, and key size validation.
- Structured logging with Zap.

## Getting Started

### Prerequisites

- Go 1.21 or later
- OpenSSL (to generate the required RSA and EC key pairs)
- Redis (for session ticket storage)

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/EronAlves1996/Recog.git
   cd Recog
   ```

2. Configure the environment:

   The application requires an RSA private key for signatures, an EC private key for the key exchange, and an AES key for session tickets. You can generate them using OpenSSL:

   ```bash
   # Generate the RSA private key
   openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048

   # Generate the EC P256 private key
   openssl ecparam -name prime256v1 -genkey -noout -out ec_private_key.pem

   # Generate a 256-bit AES key for session tickets
   openssl rand -base64 32 > aes_key.txt
   ```

   Next, create a `.env` file in the root of the project and add the base64 encoded content of your keys:

   ```bash
   # On macOS or Linux
   echo "RSA_PRIVATE_KEY=\"$(cat private_key.pem | base64)\"" > .env
   echo "EC_P256_PRIVATE_KEY=\"$(cat ec_private_key.pem | base64)\"" >> .env
   echo "AES_SESSIONTICKETS_KEY=\"$(cat aes_key.txt)\"" >> .env

   # Add Redis configuration
   echo "REDIS_URL=\"localhost:6379\"" >> .env
   echo "REDIS_DB=\"0\"" >> .env
   echo "REDIS_PASSWORD=\"\"" >> .env
   ```

   Your `.env` file should look like this (with much longer values):

   ```
   RSA_PRIVATE_KEY="MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC..."
   EC_P256_PRIVATE_KEY="MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg..."
   AES_SESSIONTICKETS_KEY="your_base64_encoded_aes_key_here"
   REDIS_URL="localhost:6379"
   REDIS_DB="0"
   REDIS_PASSWORD=""
   ```

3. Generate test certificates for certificate validation:

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

4. Start Redis:

   ```bash
   # Using Docker (recommended)
   docker-compose up -d

   # Or using a local Redis installation
   redis-server
   ```

5. Run the application:

   ```bash
   go run cmd/app/main.go
   ```

The service will start on `http://localhost:8080`.

## Usage

You can use a tool like `curl` to interact with the API, or run the provided handshake script for a complete demonstration.

### 1. Hash a File

1. Create a sample file to hash:

   ```bash
   echo "hello world" > example.txt
   ```

2. Send a `POST` request to the `/file/hash` endpoint:

   ```bash
   curl -X POST -F "file=@example.txt" http://localhost:8080/file/hash
   ```

3. You will receive a JSON response with the SHA256 hash:
   ```json
   {
     "hash": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
   }
   ```

### 2. Sign a Message

1. Send a `POST` request with a JSON body to the `/sign` endpoint:

   ```bash
   curl -X POST -H "Content-Type: application/json" \
   -d '{"message": "the quick brown fox jumps over the lazy dog"}' \
   http://localhost:8080/sign
   ```

2. You will receive a JSON response with the base64 encoded signature:
   ```json
   {
     "signature": "FqE+k...[long signature string]...="
   }
   ```

### 3. Verify a Signature

1. Use the `/verify` endpoint with the original message and the signature you received.

   ```bash
   curl -X POST -H "Content-Type: application/json" \
   -d '{"message": "the quick brown fox jumps over the lazy dog", "signature": "FqE+k...="}' \
   http://localhost:8080/verify
   ```

2. The response will indicate if the signature is valid:
   ```json
   {
     "valid": true
   }
   ```

### 4. Perform an ECDH Key Exchange with Session Tickets and Certificate Validation

This flow demonstrates how to establish a shared secret between a client and the server using an ECDH scheme, resume the session using a session ticket, and validate an X.509 certificate. **Note:** This process is best performed by a programmatic client rather than manually with `curl`.

For a complete demonstration, run the provided script:

```bash
go run cmd/scripts/handshake/main.go
```

This script will:

1. Initiate an ECDH key exchange
2. Verify the server's signature
3. Complete the key exchange
4. Retrieve a session ticket
5. Resume the session using the ticket
6. Validate a certificate chain against the trusted root CA

If you want to perform these steps manually:

1. **Initiate the Exchange**: The client requests the server's ECDH public key.

   ```bash
   curl -X POST http://localhost:8080/exchange/initiate
   ```

   The server responds with its public key and a signature:

   ```json
   {
     "payload": {
       "curve": "P-256",
       "key": "BF+...[base64 encoded public key]...="
     },
     "signature": "MIAG...[base64 encoded signature]...="
   }
   ```

2. **Complete the Exchange**: The client sends its public key to the server.

   ```bash
   # Replace CLIENT_PUBLIC_KEY with the client's base64 encoded public key
   curl -X POST -H "Content-Type: application/json" \
   -d '{"clientPublicKey": "CLIENT_PUBLIC_KEY"}' \
   http://localhost:8080/exchange/complete
   ```

3. **Retrieve Session Ticket**: The server responds with an encrypted message and a session ID.

   ```json
   {
     "message": "BASE64_ENCRYPTED_PAYLOAD",
     "sessionId": "UUID"
   }
   ```

   Use the session ID to retrieve a session ticket:

   ```bash
   # Replace SESSION_ID with the session ID from the previous response
   curl -X GET http://localhost:8080/session/ticket/SESSION_ID
   ```

   The server responds with an encrypted session ticket:

   ```json
   {
     "ticket": "BASE64_ENCRYPTED_TICKET"
   }
   ```

4. **Resume Session**: Use the ticket to resume the session:

   ```bash
   # Replace TICKET with the ticket from the previous response
   curl -X POST -H "Content-Type: application/json" \
   -d '{"sessionTicket": "TICKET"}' \
   http://localhost:8080/session/resume
   ```

5. **Validate Certificate**: Use the established session to validate a certificate chain:

   ```bash
   # This step requires encrypting the request with the shared secret
   # It's best demonstrated by running the handshake script
   ```

## API Reference

### POST /file/hash

Calculates the SHA256 hash of a provided file.

**Request:**

- **Method:** `POST`
- **URL:** `/file/hash`
- **Headers:** `Content-Type: multipart/form-data`
- **Body:** Form field named `file` containing the file to be hashed.

**Success Response (200 OK):**

- **Content-Type:** `application/json`
- **Body:** A JSON object with a `hash` key.

  ```json
  {
    "hash": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
  }
  ```

### POST /sign

Signs a text message using the configured RSA private key.

**Request:**

- **Method:** `POST`
- **URL:** `/sign`
- **Headers:** `Content-Type: application/json`
- **Body:** A JSON object with a `message` key.

  ```json
  {
    "message": "a message to sign"
  }
  ```

**Success Response (200 OK):**

- **Content-Type:** `application/json`
- **Body:** A JSON object with a `signature` key.

  ```json
  {
    "signature": "base64-encoded-signature-string"
  }
  ```

### POST /verify

Verifies a digital signature against a message using the configured RSA public key.

**Request:**

- **Method:** `POST`
- **URL:** `/verify`
- **Headers:** `Content-Type: application/json`
- **Body:** A JSON object with `message` and `signature` keys.

  ```json
  {
    "message": "a message to sign",
    "signature": "base64-encoded-signature-string"
  }
  ```

**Success Response (200 OK):**

- **Content-Type:** `application/json`
- **Body:** A JSON object with a `valid` boolean key.

  ```json
  {
    "valid": true
  }
  ```

### POST /exchange/initiate

Initiates an ECDH key exchange by providing the server's ECDH public key, signed for authenticity.

**Request:**

- **Method:** `POST`
- **URL:** `/exchange/initiate`
- **Body:** Empty

**Success Response (200 OK):**

- **Content-Type:** `application/json`
- **Body:** A JSON object with `payload` and `signature` keys.

  ```json
  {
    "payload": {
      "curve": "P-256",
      "key": "base64-encoded-ecdh-public-key"
    },
    "signature": "base64-encoded-signature-of-payload"
  }
  ```

### POST /exchange/complete

Completes the ECDH key exchange by receiving the client's public key and returning a proof of the derived shared secret.

**Request:**

- **Method:** `POST`
- **URL:** `/exchange/complete`
- **Headers:** `Content-Type: application/json`
- **Body:** A JSON object with the `clientPublicKey` key.

  ```json
  {
    "clientPublicKey": "base64-encoded-client-ecdh-public-key"
  }
  ```

**Success Response (200 OK):**

- **Content-Type:** `application/json`
- **Body:** A JSON object with a `message` key containing an encrypted payload and a `sessionId` key.

  ```json
  {
    "message": "base64-encoded-aes-gcm-encrypted-message",
    "sessionId": "uuid-session-id"
  }
  ```

### GET /session/ticket/:id

Retrieves a session ticket for the given session ID.

**Request:**

- **Method:** `GET`
- **URL:** `/session/ticket/:id`
- **Path Parameters:** `id` - The session ID

**Success Response (200 OK):**

- **Content-Type:** `application/json`
- **Body:** A JSON object with a `ticket` key.

  ```json
  {
    "ticket": "base64-encoded-session-ticket"
  }
  ```

### POST /session/resume

Resumes a session using a session ticket.

**Request:**

- **Method:** `POST`
- **URL:** `/session/resume`
- **Headers:** `Content-Type: application/json`
- **Body:** A JSON object with a `sessionTicket` key.

  ```json
  {
    "sessionTicket": "base64-encoded-session-ticket"
  }
  ```

**Success Response (200 OK):**

- **Content-Type:** `application/json`
- **Body:** Empty

### POST /certificate/validate

Validates an X.509 certificate chain against a trusted root CA. This endpoint requires a valid session ticket and encrypts the request/response using the shared secret from the ECDH exchange.

The validation process includes:

- Certificate chain verification against the trusted root CA
- OCSP (Online Certificate Status Protocol) revocation checking for each certificate in the chain
- Signature algorithm verification (accepts only SHA256WithRSA, SHA384WithRSA, SHA512WithRSA)
- RSA key size validation (minimum 2048 bits)

**Request:**

- **Method:** `POST`
- **URL:** `/certificate/validate`
- **Headers:**
  - `Content-Type: application/json`
  - `X-Session-Ticket: [base64-encoded-session-ticket]`
- **Body:** An encrypted JSON object with a `certificate` key containing a base64-encoded certificate chain.

**Success Response (200 OK):**

- **Content-Type:** `application/json`
- **Body:** An encrypted JSON object with a `valid` boolean key.

  ```json
  {
    "valid": true
  }
  ```

**Error Responses:**

- `400 Bad Request`: Missing `Content-Type` header or invalid request body.
- `401 Unauthorized`: No session ticket found or invalid session.
- `403 Forbidden`: Session expired.
- `415 Unsupported Media Type`: Incorrect `Content-Type` for `/file/hash`.
- `500 Internal Server Error`: Server-side issues during processing.

## Roadmap

This project is intended to grow. Future planned features include:

- Certificate hostname validation
- CRL (Certificate Revocation List) support as a fallback to OCSP
- Support for ECDSA and other key types in certificate validation
- Certificate chain depth validation
- Soft-fail behavior for OCSP checking
- Support for multiple trusted root CAs
- Certificate transparency logging
- Key Derivation Function (HKDF) for secure key generation.
- Ephemeral ECDH key exchange for forward secrecy.
- Key rotation mechanisms for session tickets.
- Support for multiple hash algorithms (MD5, SHA1, SHA512).
- Text string hashing endpoint.
- JWT generation and validation.
- Implementation of basic security controls (rate limiting, CORS).
- Add support for multiple elliptic curves (e.g., X25519).
- Implement robust session management for key exchanges.

## Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are greatly appreciated.

Feel free to open an issue for suggestions or submit a pull request.
