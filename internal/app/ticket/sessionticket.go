package ticket

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type SessionTicket struct {
	ExpiresAt time.Time
	SessionID uuid.UUID
	Secret    []byte
}

func (s *SessionTicket) Encode() ([]byte, error) {
	var bytes bytes.Buffer
	if err := gob.NewEncoder(&bytes).Encode(*s); err != nil {
		return nil, fmt.Errorf("unable to encode session ticket: %w", err)
	}

	return bytes.Bytes(), nil
}

func Decode(target []byte) (*SessionTicket, error) {
	var bytes bytes.Buffer
	bytes.Write(target)

	var ss SessionTicket

	if err := gob.NewDecoder(&bytes).Decode(&ss); err != nil {
		return nil, fmt.Errorf("unable to decode session ticket: %w", err)
	}

	return &ss, nil
}
