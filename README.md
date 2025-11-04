# Recog

A Go-based playground for security and cryptography concepts.

## Overview

Recog is a service designed to experiment with and demonstrate various security and cryptographic primitives. Currently in its embryonic stage, its initial feature is a simple file hashing service. The project is built with Go and the Gin web framework, and it's intended to evolve, incorporating more security experiments as it grows.

## Features

- Calculate SHA256 hash of uploaded files.
- Simple RESTful API endpoint.
- Structured logging with Zap.

## Getting Started

### Prerequisites

- Go 1.25.3 or later

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/EronAlves1996/Recog.git
   cd Recog
   ```

2. Run the application:
   ```bash
   go run main.go
   ```

The service will start on `http://localhost:8080`.

## Usage

You can use a tool like `curl` to interact with the API.

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
     "Hash": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
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
- **Body:** A JSON object with a `Hash` key.

  ```json
  {
    "Hash": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
  }
  ```

**Error Responses:**

- `400 Bad Request`: Missing `Content-Type` header.
- `415 Unsupported Media Type`: Incorrect `Content-Type`.
- `500 Internal Server Error`: Server-side issues during processing.

## Roadmap

This project is intended to grow. Future planned features include:

- Support for multiple hash algorithms (MD5, SHA1, SHA512).
- Text string hashing endpoint.
- Symmetric encryption/decryption (AES).
- Asymmetric encryption/decryption (RSA).
- JWT generation and validation.
- Implementation of basic security controls (rate limiting, CORS).

## Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are greatly appreciated.

Feel free to open an issue for suggestions or submit a pull request.

## License

[MIT](LICENSE)
