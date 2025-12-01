package certificate

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/EronAlves1996/Recog/internal/app/base"
)

type validateCertificateAction struct{}

var _ base.Action[[]byte, bool] = validateCertificateAction{}

func NewValidateCertificateAction() *validateCertificateAction {
	return &validateCertificateAction{}
}

// Execute implements base.Action.
func (v validateCertificateAction) Execute(ctx context.Context, in *[]byte) (*bool, error) {
	block, _ := pem.Decode(*in)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate")
	}

	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse certifice: %w", err)
	}

	rootCa, err := os.ReadFile("ca.crt")
	if err != nil {
		return nil, fmt.Errorf("unable to read root ca file: %w", err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(rootCa)

	verifyOptions := x509.VerifyOptions{
		// Already validate the entire chain
		Roots: caCertPool,
	}

	chains, err := certificate.Verify(verifyOptions)
	if err != nil {
		return nil, fmt.Errorf("unable to verify certificate chain: %w", err)
	}

	valid := len(chains) > 0
	return &valid, nil
}
