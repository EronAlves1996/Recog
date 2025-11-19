package exchange

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"time"

	"github.com/EronAlves1996/Recog/internal/app/ticket"
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
	aesSessionTicketKey []byte,
) *CompleteExchangeAction {
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

	sessionTicket := ticket.SessionTicket{
		ExpiresAt: timestamp,
		SessionID: sessionID,
		Secret:    secret,
	}

	encoded, err := sessionTicket.Encode()

	if err != nil {
		return nil, fmt.Errorf("unable to encode session ticket")
	}

	encryptedSessionTicket, err := encrypt(c.aesSessionTicketKey, encoded)
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
