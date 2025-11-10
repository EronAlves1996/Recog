package signature

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"

	"github.com/EronAlves1996/Recog/internal/pkg/cryptoutils"
	"go.uber.org/zap"
)

type SignBytesRsaAction struct {
	rsaPair *cryptoutils.RsaPair
	l       *zap.SugaredLogger
}

func NewSignBytesRsaAction(rsaPair *cryptoutils.RsaPair, logger *zap.SugaredLogger) *SignBytesRsaAction {
	return &SignBytesRsaAction{
		rsaPair: rsaPair,
		l:       logger,
	}
}

func (s *SignBytesRsaAction) Execute(reader *io.Reader) (*[]byte, error) {
	sha256 := crypto.SHA256.New()
	if _, err := io.Copy(sha256, *reader); err != nil {
		s.l.Errorw("Unable to hash the message", zap.Error(err))
		return nil, fmt.Errorf("unable to hash the message: %w", err)
	}

	digest := sha256.Sum(nil)

	signature, err := rsa.SignPSS(rand.Reader, s.rsaPair.PrivateKey, crypto.SHA256, digest, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to sign the hash: %w", err)
	}

	return &signature, nil
}
