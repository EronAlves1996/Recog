package exchange

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"github.com/EronAlves1996/Recog/internal/app/base"
	"go.uber.org/zap"
)

type InitiateExchangeAction struct {
	logger            *zap.SugaredLogger
	ecdhPrivateKey    *ecdh.PrivateKey
	signMessageAction base.Action[io.Reader, []byte]
}

func NewInitiateExchangeAction(l *zap.SugaredLogger,
	e *ecdh.PrivateKey,
	signMessageAction base.Action[io.Reader, []byte],
) *InitiateExchangeAction {
	return &InitiateExchangeAction{
		logger:            l,
		ecdhPrivateKey:    e,
		signMessageAction: signMessageAction,
	}
}

type EcdhPayload struct {
	Curve string
	Key   string
}

type InitiateExchangeActionReturn struct {
	Payload   EcdhPayload
	Signature string
}

func (i *InitiateExchangeAction) Execute(value *base.Void) (*InitiateExchangeActionReturn, error) {
	publicKey := i.ecdhPrivateKey.PublicKey()
	keyBytes := publicKey.Bytes()
	stringKey := base64.StdEncoding.EncodeToString(keyBytes)
	payload := EcdhPayload{
		Key:   stringKey,
		Curve: "P-256",
	}

	var buf bytes.Buffer

	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal json")
	}

	buf.Write(encoded)

	var reader io.Reader = &buf
	signature, err := i.signMessageAction.Execute(&reader)

	if err != nil {
		return nil, fmt.Errorf("unable to generate signature: %w", err)
	}

	ret := InitiateExchangeActionReturn{
		Payload:   payload,
		Signature: base64.StdEncoding.EncodeToString(*signature),
	}

	return &ret, nil
}
