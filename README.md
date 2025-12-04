# Recog

A Go-based playground for security and cryptography concepts.

## Overview

Recog is a service designed to experiment with and demonstrate various security and cryptographic primitives. It provides a simple RESTful API to interact with concepts like hashing, digital signatures, secure key exchange, session management, certificate validation, and rate limiting. The project is built with Go and the Gin web framework, and it's intended to evolve, incorporating more security experiments as it grows.

## Features

- Calculate SHA256 hash of uploaded files and text messages (both public and encrypted endpoints)
- Sign and verify text messages with an RSA key pair
- Perform an ECDH key exchange for secure session establishment
- Session ticket management for efficient session resumption
- X.509 certificate validation with OCSP revocation checking, signature algorithm verification, and key size validation
- **Rate limiting** using token bucket algorithm for API endpoints
- **Request/response encryption** for secure endpoints using session-based AES-GCM encryption
- Structured logging with Zap
- Input validation with custom validation rules

## Getting Started

### Prerequisites

- Go 1.21 or later
- OpenSSL (to generate the required RSA and EC key pairs)
- Redis (for session ticket storage and rate limiting)

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/EronAlves1996/Recog.git
   cd Recog
   ```

2. Configure the environment:

   ```bash
   # Generate the required keys
   openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
   openssl ecparam -name prime256v1 -genkey -noout -out ec_private_key.pem
   openssl rand -base64 32 > aes_key.txt

   # Create .env file
   echo "RSA_PRIVATE_KEY=\"$(cat private_key.pem | base64)\"" > .env
   echo "EC_P256_PRIVATE_KEY=\"$(cat ec_private_key.pem | base64)\"" >> .env
   echo "AES_SESSIONTICKETS_KEY=\"$(cat aes_key.txt)\"" >> .env
   echo "REDIS_URL=\"localhost:6379\"" >> .env
   echo "REDIS_DB=\"0\"" >> .env
   echo "REDIS_PASSWORD=\"\"" >> .env
   ```

3. Start Redis:

   ```bash
   # Using Docker (recommended)
   docker-compose up -d
   ```

4. Run the application:

   ```bash
   go run cmd/app/main.go
   ```

The service will start on `http://localhost:8080`.

## Usage

### Basic Endpoints

#### 1. Hash a File

```bash
echo "hello world" > example.txt
curl -X POST -F "file=@example.txt" http://localhost:8080/file/hash
```

#### 2. Hash a Message (Public)

**Note: This endpoint is rate-limited (50 requests per 10-minute window).**

```bash
curl -X POST -H "Content-Type: application/json" \
-d '{"message": "the quick brown fox jumps over the lazy dog"}' \
http://localhost:8080/message/hash
```

#### 3. Sign a Message

```bash
curl -X POST -H "Content-Type: application/json" \
-d '{"message": "test message"}' \
http://localhost:8080/sign
```

#### 4. Verify a Signature

```bash
curl -X POST -H "Content-Type: application/json" \
-d '{"message": "test message", "signature": "base64-signature-here"}' \
http://localhost:8080/verify
```

### Secure Endpoints

Secure endpoints require a session ticket obtained through ECDH key exchange. Requests and responses are encrypted using AES-GCM with session-specific keys.

For a complete demonstration of secure endpoints including key exchange, session management, and certificate validation:

```bash
go run cmd/scripts/handshake/main.go
```

This script demonstrates:

1. ECDH key exchange
2. Session ticket retrieval
3. Certificate validation with encryption
4. Encrypted request/response flow

### New: Encrypted Message Hashing

After establishing a session via ECDH exchange, you can use the encrypted endpoint:

```bash
# Requires a valid session ticket in X-Session-Ticket header
curl -X POST http://localhost:8080/message/hash/secure \
  -H "X-Session-Ticket: [base64-encoded-session-ticket]" \
  -H "Content-Type: application/json" \
  --data-binary [encrypted-request-body]
```

**Note:** Both request and response bodies are encrypted using the session's shared secret.

## API Reference

### Public Endpoints

#### POST /file/hash

Calculates SHA256 hash of uploaded file.

#### POST /message/hash

Calculates SHA256 hash of text message (rate-limited).

#### POST /sign

Signs message with RSA private key.

#### POST /verify

Verifies digital signature.

### Secure Endpoints (Require Session)

#### POST /exchange/initiate

Initiates ECDH key exchange.

#### POST /exchange/complete

Completes ECDH key exchange, returns session ID.

#### GET /session/ticket/:id

Retrieves session ticket.

#### POST /session/resume

Resumes session with ticket.

#### POST /certificate/validate

Validates X.509 certificate chain with encryption.

#### POST /message/hash/secure

**New**: Encrypted endpoint for message hashing.

**Request:**

- Headers: `X-Session-Ticket: [base64-ticket]`, `Content-Type: application/json`
- Body: Encrypted JSON `{"message": "text to hash"}`

**Response:**

- Content-Type: `application/octet-stream`
- Body: Encrypted JSON `{"hash": "sha256-hash"}`

## Security Architecture

### Encryption Implementation

- **Session-based encryption**: Each session establishes unique AES keys via ECDH
- **AES-GCM**: Provides both confidentiality and integrity
- **Secure key exchange**: ECDH P-256 for forward secrecy
- **Middleware-based**: Clean integration with existing rate limiting and validation

### Validation & Protection

- Input validation with custom rules
- Rate limiting with Redis persistence
- Certificate validation with OCSP revocation checking
- Session expiration and ticket encryption

## Roadmap

### High Priority

- **Replay attack protection** via nonce/timestamp in encrypted payloads
- **Key derivation with HKDF** for stronger key generation from ECDH shared secrets
- **Key rotation mechanisms** for long-lived sessions

### Medium Priority

- **Certificate transparency logging** support
- **Multiple elliptic curve support** (X25519, P-384)
- **JWT generation and validation** endpoints

### Future Considerations

- **Chunked encryption** for large file support
- **Certificate hostname validation**
- **CRL support** as OCSP fallback
- **Enhanced session management** with refresh tokens

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

For security-related changes, please include a threat model analysis.

```

```
