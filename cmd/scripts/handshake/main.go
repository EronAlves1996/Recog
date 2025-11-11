package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/EronAlves1996/Recog/internal/app/exchange"
)

type VerifyPayload struct {
	Message   any    `json:"message"`
	Signature string `json:"signature"`
}

type VerifyPayloadReturn struct {
	Valid bool `json:"valid"`
}

type ClientSecretRequest struct {
	ClientPublicKey string `json:"clientPublicKey"`
}

type CompleteExchangeActionReturn struct {
	Message string `json:"message"`
}

var logger = log.Default()

func main() {
	logger.Println("initiating exchange")
	resp, err := http.Post("http://127.0.0.1:8080/exchange/initiate", "application/json", http.NoBody)
	if err != nil {
		log.Fatal(fmt.Errorf("unable to call exchange url: %w", err))
	}
	defer resp.Body.Close()

	var exchangePayload exchange.InitiateExchangeActionReturn
	if err := json.NewDecoder(resp.Body).Decode(&exchangePayload); err != nil {
		log.Fatal(fmt.Errorf("unable to decode exchange initiate payload: %w", err))
	}
	logger.Println("payload received")

	verifyPayload := VerifyPayload{
		Message:   exchangePayload.Payload,
		Signature: exchangePayload.Signature,
	}

	logger.Println("verifying payload signature")

	buf := new(bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(verifyPayload); err != nil {
		log.Fatal(fmt.Errorf("unable to marshall the verify message: %w", err))
	}

	response, err := http.Post("http://127.0.0.1:8080/verify", "application/json", buf)
	if err != nil {
		log.Fatal(fmt.Errorf("unable to verify signature of payload %w", err))
	}
	defer response.Body.Close()

	logger.Println("received verification result")
	var result VerifyPayloadReturn

	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		log.Fatal(fmt.Errorf("unable to desserialize verification result"))
	}

	if !result.Valid {
		log.Fatalln("handshake initiation signature invalid")
	}

	logger.Println("signature verification succeeded")

	decodedBase64ServerPublicKey, err := base64.StdEncoding.DecodeString(exchangePayload.Payload.Key)
	if err != nil {
		log.Fatal(fmt.Errorf("unable to decode public server key: %w", err))
	}

	serverPublicKey, err := ecdh.P256().NewPublicKey(decodedBase64ServerPublicKey)
	if err != nil {
		log.Fatal(fmt.Errorf("unable to get public key from payload: %w", err))
	}

	logger.Println("server public key decoded")

	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(fmt.Errorf("unable to generate a new ecdh private key: %w", err))
	}

	publicKey := privateKey.PublicKey()
	pubKeyBytes := publicKey.Bytes()

	clientSecretRequest := ClientSecretRequest{
		ClientPublicKey: base64.StdEncoding.EncodeToString(pubKeyBytes),
	}
	var clientSecretRequestBuf bytes.Buffer
	if err := json.NewEncoder(&clientSecretRequestBuf).Encode(clientSecretRequest); err != nil {
		log.Fatal(fmt.Errorf("unable to marshal the secret to send server: %w", err))
	}

	logger.Println("sending client public key")

	exchangeCompleteResponse, err := http.Post("http://127.0.0.1:8080/exchange/complete", "application/json", &clientSecretRequestBuf)
	if err != nil {
		log.Fatal(fmt.Errorf("unable to complete handhsake: %w", err))
	}
	defer exchangeCompleteResponse.Body.Close()

	var decodedEncryptedMessage CompleteExchangeActionReturn
	if err := json.NewDecoder(exchangeCompleteResponse.Body).Decode(&decodedEncryptedMessage); err != nil {
		log.Fatal(fmt.Errorf("unable to parse the complete exchange action: %w", err))
	}
	logger.Println("decrypting received message")

	sharedSecret, err := privateKey.ECDH(serverPublicKey)
	if err != nil {
		log.Fatal(fmt.Errorf("unable to generate a shared secret with both keys: %w", err))
	}

	ciphertext, err := base64.StdEncoding.DecodeString(decodedEncryptedMessage.Message)
	if err != nil {
		log.Fatal(fmt.Errorf("unable to get base64 encrypted message: %w", err))
	}

	block, err := aes.NewCipher(sharedSecret)
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

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Fatal(fmt.Errorf("unable to unencrypt message: %w", err))
	}

	logger.Printf("message decrypted: %s", string(plaintext))
}
