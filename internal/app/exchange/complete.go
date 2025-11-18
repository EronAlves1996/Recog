package exchange

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

type CompleteExchangeAction struct {
	ecdhPrivateKey      *ecdh.PrivateKey
	redisClient         *redis.Client
	aesSessionTicketKey []byte
}

func NewCompleteExchangeAction(ecdhPrivateKey *ecdh.PrivateKey,
	redisClient *redis.Client,
	aesSessionTicketKey []byte) *CompleteExchangeAction {
	return &CompleteExchangeAction{
		ecdhPrivateKey:      ecdhPrivateKey,
		redisClient:         redisClient,
		aesSessionTicketKey: aesSessionTicketKey,
	}
}

func encrypt(secret []byte, plainText []byte) ([]byte, error) {

	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to generate aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("unable to generate gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to initialize the intialization vector: %w", err)
	}

	return gcm.Seal(nonce, nonce, plainText, nil), nil
}

type CompleteExchangeActionReturn struct {
	Message   string `json:"message"`
	SessionID string `json:"sessionId"`
}

func (c *CompleteExchangeAction) Execute(ctx context.Context, clientKey *string) (*CompleteExchangeActionReturn, error) {
	decoded, err := base64.StdEncoding.DecodeString(*clientKey)
	if err != nil {
		return nil, fmt.Errorf("unable to decoded the base64 client key: %w", err)
	}

	publicKey, err := ecdh.P256().NewPublicKey(decoded)
	if err != nil {
		return nil, fmt.Errorf("unable to convert ecdsa public key to ecdh public key")
	}

	secret, err := c.ecdhPrivateKey.ECDH(publicKey)
	if err != nil {
		return nil, fmt.Errorf("unable to parse the secret: %w", err)
	}

	cipherText, err := encrypt(secret, []byte("handshake complete"))
	if err != nil {
		return nil, fmt.Errorf("unable to encrypt text: %w", err)
	}

	sessionID, err := uuid.NewUUID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate a new session id: %w", err)
	}

	timestamp := time.Now().Add(time.Minute * 10)
	encodedTimestamp, err := timestamp.GobEncode()

	if err != nil {
		return nil, fmt.Errorf("failed to encode session ttl: %w", err)
	}

	timestampLen := len(encodedTimestamp)

	encodedSessionID, err := sessionID.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to encode session ID: %w", err)
	}

	sessionIDLen := len(encodedSessionID)

	// The message format is described as
	//
	// | 8              | timestamp-size | 8             | sessionID-size | secret
	// | timestamp-size | ttl-timestamp | sessionID-size | sessionID      | secret
	var message bytes.Buffer

	if err := binary.Write(&message, binary.LittleEndian, int64(timestampLen)); err != nil {
		return nil, fmt.Errorf("failed to encode session ticket: %w", err)
	}
	message.Write(encodedTimestamp)

	if err := binary.Write(&message, binary.LittleEndian, int64(sessionIDLen)); err != nil {
		return nil, fmt.Errorf("failed to encode session ticket: %w", err)
	}
	message.Write(encodedSessionID)
	message.Write(secret)

	encryptedSessionTicket, err := encrypt(c.aesSessionTicketKey, message.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt session ticket: %w", err)
	}

	fiveMinutes := 5 * time.Minute

	// The session parameters have
	c.redisClient.Set(ctx, sessionID.String(), encryptedSessionTicket, fiveMinutes)

	return &CompleteExchangeActionReturn{
		Message:   base64.StdEncoding.EncodeToString(cipherText),
		SessionID: sessionID.String(),
	}, nil
}
