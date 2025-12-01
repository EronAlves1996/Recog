package certificate

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"

	"github.com/EronAlves1996/Recog/internal/app/base"
	"golang.org/x/crypto/ocsp"
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

	if len(chains) <= 0 {
		v := false
		return &v, nil
	}

	ocspValid, err := validateOcspRevogation(chains)
	if err != nil {
		return nil, fmt.Errorf("unable to verify ocsp revogation: %w", err)
	}

	if !ocspValid {
		v := false
		return &v, nil
	}

	if !validateCertificateSignatureAlgorithm(certificate) {
		v := false
		return &v, nil
	}

	parsed, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unable to parse public key")
	}

	if parsed.Size() < 2048 {
		v := false
		return &v, nil
	}

	l := true
	return &l, nil
}

var validSignatureAlgorithms = []x509.SignatureAlgorithm{
	x509.SHA256WithRSA,
	x509.SHA384WithRSA,
	x509.SHA512WithRSA,
}

func validateCertificateSignatureAlgorithm(certificate *x509.Certificate) bool {
	return slices.Contains(validSignatureAlgorithms, certificate.SignatureAlgorithm)
}

func validateOcspCertificatePair(certificate, issuer *x509.Certificate) (bool, error) {
	opts := ocsp.RequestOptions{
		Hash: crypto.SHA256,
	}

	if len(certificate.OCSPServer) == 0 {
		return true, nil
	}

	if certificate.OCSPServer[0] == "" {
		return true, nil
	}

	buffer, err := ocsp.CreateRequest(certificate, issuer, &opts)
	if err != nil {
		return false, fmt.Errorf("unable to create ocsp revogation request: %w", err)
	}

	httpRequest, err := http.NewRequest(http.MethodPost, certificate.OCSPServer[0], bytes.NewBuffer(buffer))
	if err != nil {
		return false, err
	}

	ocspURL, err := url.Parse(certificate.OCSPServer[0])
	if err != nil {
		return false, err
	}
	httpRequest.Header.Add("Content-Type", "application/ocsp-request")
	httpRequest.Header.Add("Accept", "application/ocsp-response")
	httpRequest.Header.Add("host", ocspURL.Host)

	httpClient := &http.Client{}
	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		return false, err
	}
	defer httpResponse.Body.Close()
	output, err := io.ReadAll(httpResponse.Body)

	if err != nil {
		return false, err
	}

	ocspResponse, err := ocsp.ParseResponseForCert(output, certificate, issuer)
	if err != nil {
		return false, err
	}

	if ocspResponse.Status == ocsp.Good {
		return true, nil
	}

	return false, nil
}

func validateOcspRevogation(chains [][]*x509.Certificate) (bool, error) {

	for _, v := range chains {
		chainSize := len(v)
		for i := range v {
			if (i + 1) == chainSize {
				break
			}

			valid, err := validateOcspCertificatePair(v[i], v[i+1])
			if err != nil {
				return false, fmt.Errorf("unable to validate pair: %w", err)
			}

			if !valid {
				return false, nil
			}
		}
	}

	return true, nil
}
