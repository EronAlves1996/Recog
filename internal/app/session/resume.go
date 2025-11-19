package session

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"log"

	"github.com/EronAlves1996/Recog/internal/app/base"
	"github.com/EronAlves1996/Recog/internal/app/ticket"
)

type resumeSessionAction struct {
	aesSessionTicketKey []byte
}

func NewResumeSessionAction(aesSessionTicketKey []byte) *resumeSessionAction {
	return &resumeSessionAction{
		aesSessionTicketKey: aesSessionTicketKey,
	}
}

var _ base.Action[string, base.Void] = resumeSessionAction{}

// Execute implements base.Action.
func (r resumeSessionAction) Execute(ctx context.Context, ticketEncoded *string) (*base.Void, error) {
	decodedTicket, err := base64.StdEncoding.DecodeString(*ticketEncoded)

	if err != nil {
		return nil, fmt.Errorf("failed to decode ticket: %w", err)
	}

	marshalledSs, err := decrypt(r.aesSessionTicketKey, decodedTicket)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt session ticket: %w", err)
	}

	if _, err := ticket.Decode(marshalledSs); err != nil {
		return nil, fmt.Errorf("unable to unmarshal session ticket: %w", err)
	}

	return nil, nil

}

func decrypt(secret []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		log.Fatal(fmt.Errorf("unable to make aes cipher: %w", err))
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(fmt.Errorf("unable to make gcm: %w", err))
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		log.Fatal(fmt.Errorf("ciphertext too short"))
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	return gcm.Open(nil, nonce, ciphertext, nil)
}
