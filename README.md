# Recog

A Go-based playground for security and cryptography concepts.

## Overview

Recog is a service designed to experiment with and demonstrate various security and cryptographic primitives. It provides a simple RESTful API to interact with concepts like hashing and digital signatures. The project is built with Go and the Gin web framework, and it's intended to evolve, incorporating more security experiments as it grows.

## Features

- Calculate SHA256 hash of uploaded files.
- Sign text messages with an RSA private key.
- Verify digital signatures using an RSA public key.
- Structured logging with Zap.

## Getting Started

### Prerequisites

- Go 1.25.3 or later
- OpenSSL (to generate the required RSA key pair)

### Installation

1. Clone the repository:

```bash
   git clone https://github.com/EronAlves1996/Recog.git
   cd Recog
```

2. Configure the environment:

   The application requires an RSA private key to run. You can generate a new one using OpenSSL:

   ```bash
   openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
   ```

   Next, create a `.env` file in the root of the project and add the base64 encoded content of your private key:

   ```bash
   # On macOS or Linux
   cat private_key.pem | base64 > .env

   # On Windows (Command Prompt)
   certutil -encode private_key.pem temp.b64 && findstr /v /c:- temp.b64 > .env && del temp.b64
   ```

   Your `.env` file should look like this (with a much longer value):

   ```
   RSA_PRIVATE_KEY="MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC..."
   ```

3. Run the application:
   ```bash
   go run main.go
   ```

The service will start on `http://localhost:8080`.

## Usage

You can use a tool like `curl` to interact with the API.

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

   If you tamper with the message, the verification will fail:

   ```bash
   curl -X POST -H "Content-Type: application/json" \
   -d '{"message": "the quick brown fox jumps over the lazy cat", "signature": "FqE+k...="}' \
   http://localhost:8080/verify
   ```

   ```json
   {
     "valid": false
   }
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

**Error Responses:**

- `400 Bad Request`: Missing `Content-Type` header or invalid request body.
- `415 Unsupported Media Type`: Incorrect `Content-Type` for `/file/hash`.
- `500 Internal Server Error`: Server-side issues during processing.

## Roadmap

This project is intended to grow. Future planned features include:

- Support for multiple hash algorithms (MD5, SHA1, SHA512).
- Text string hashing endpoint.
- Symmetric encryption/decryption (AES).
- JWT generation and validation.
- Implementation of basic security controls (rate limiting, CORS).

## Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are greatly appreciated.

Feel free to open an issue for suggestions or submit a pull request.

```

```
