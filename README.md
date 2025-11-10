# Recog

A Go-based playground for security and cryptography concepts.

## Overview

Recog is a service designed to experiment with and demonstrate various security and cryptographic primitives. It provides a simple RESTful API to interact with concepts like hashing, digital signatures, and secure key exchange. The project is built with Go and the Gin web framework, and it's intended to evolve, incorporating more security experiments as it grows.

## Features

- Calculate SHA256 hash of uploaded files.
- Sign and verify text messages with an RSA key pair.
- Perform an ECDH key exchange for secure session establishment.
- Structured logging with Zap.

## Getting Started

### Prerequisites

- Go 1.21 or later
- OpenSSL (to generate the required RSA and EC key pairs)

### Installation

1.  Clone the repository:

    ```bash
    git clone https://github.com/EronAlves1996/Recog.git
    cd Recog
    ```

2.  Configure the environment:

    The application requires an RSA private key for signatures and an EC private key for the key exchange. You can generate them using OpenSSL:

    ```bash
    # Generate the RSA private key
    openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048

    # Generate the EC P256 private key
    openssl ecparam -name prime256v1 -genkey -noout -out ec_private_key.pem
    ```

    Next, create a `.env` file in the root of the project and add the base64 encoded content of your keys:

    ```bash
    # On macOS or Linux
    echo "RSA_PRIVATE_KEY=\"$(cat private_key.pem | base64)\"" > .env
    echo "EC_P256_PRIVATE_KEY=\"$(cat ec_private_key.pem | base64)\"" >> .env

    # On Windows (Command Prompt)
    certutil -encode private_key.pem temp.b64 && findstr /v /c:- temp.b64 > temp_rsa.b64 && del temp.b64
    certutil -encode ec_private_key.pem temp.b64 && findstr /v /c:- temp.b64 > temp_ec.b64 && del temp.b64
    echo RSA_PRIVATE_KEY="> .env && type temp_rsa.b64 >> .env
    echo EC_P256_PRIVATE_KEY=">> .env && type temp_ec.b64 >> .env
    del temp_rsa.b64 temp_ec.b64
    ```

    Your `.env` file should look like this (with much longer values):

    ```
    RSA_PRIVATE_KEY="MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC..."
    EC_P256_PRIVATE_KEY="MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg..."
    ```

3.  Run the application:

    ```bash
    go run main.go
    ```

The service will start on `http://localhost:8080`.

## Usage

You can use a tool like `curl` to interact with the API.

### 1. Hash a File

1.  Create a sample file to hash:

    ```bash
    echo "hello world" > example.txt
    ```

2.  Send a `POST` request to the `/file/hash` endpoint:

    ```bash
    curl -X POST -F "file=@example.txt" http://localhost:8080/file/hash
    ```

3.  You will receive a JSON response with the SHA256 hash:
    ```json
    {
      "hash": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    }
    ```

### 2. Sign a Message

1.  Send a `POST` request with a JSON body to the `/sign` endpoint:

    ```bash
    curl -X POST -H "Content-Type: application/json" \
    -d '{"message": "the quick brown fox jumps over the lazy dog"}' \
    http://localhost:8080/sign
    ```

2.  You will receive a JSON response with the base64 encoded signature:
    ```json
    {
      "signature": "FqE+k...[long signature string]...="
    }
    ```

### 3. Verify a Signature

1.  Use the `/verify` endpoint with the original message and the signature you received.

    ```bash
    curl -X POST -H "Content-Type: application/json" \
    -d '{"message": "the quick brown fox jumps over the lazy dog", "signature": "FqE+k...="}' \
    http://localhost:8080/verify
    ```

2.  The response will indicate if the signature is valid:
    ```json
    {
      "valid": true
    }
    ```

### 4. Perform an ECDH Key Exchange

This flow demonstrates how to establish a shared secret between a client and the server using an ECDH scheme. **Note:** This process is best performed by a programmatic client rather than manually with `curl`.

1.  **Initiate the Exchange**: The client requests the server's ECDH public key.

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

2.  **Client-Side Processing**:

    - The client verifies the `signature` using the server's known RSA public key to ensure the key is authentic.
    - The client generates its own ECDH key pair.
    - The client computes the shared secret using its private key and the server's public key.

3.  **Complete the Exchange**: The client sends its public key to the server.

    ```bash
    # Replace CLIENT_PUBLIC_KEY with the client's base64 encoded public key
    curl -X POST -H "Content-Type: application/json" \
    -d '{"clientPublicKey": "CLIENT_PUBLIC_KEY"}' \
    http://localhost:8080/exchange/complete
    ```

4.  **Verify the Handshake**: The server computes the same shared secret, encrypts a message with it, and sends it back.

    ```json
    {
      "message": "BASE64_ENCRYPTED_PAYLOAD"
    }
    ```

    The client decrypts this message using the shared secret. If the decrypted message is "handshake complete", the exchange was successful.

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
- **Body:** A JSON object with a `message` key containing an encrypted payload.

  ```json
  {
    "message": "base64-encoded-aes-gcm-encrypted-message"
  }
  ```

**Error Responses:**

- `400 Bad Request`: Missing `Content-Type` header or invalid request body.
- `415 Unsupported Media Type`: Incorrect `Content-Type` for `/file/hash`.
- `500 Internal Server Error`: Server-side issues during processing.

## Roadmap

This project is intended to grow. Future planned features include:

- Ephemeral ECDH key exchange for forward secrecy.
- AES-GCM for symmetric encryption.
- Key Derivation Function (HKDF) for secure key generation.
- Support for multiple hash algorithms (MD5, SHA1, SHA512).
- Text string hashing endpoint.
- JWT generation and validation.
- Implementation of basic security controls (rate limiting, CORS).
- Add support for multiple elliptic curves (e.g., X25519).
- Implement robust session management for key exchanges.

## Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are greatly appreciated.

Feel free to open an issue for suggestions or submit a pull request.
