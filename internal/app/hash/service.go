package hash

import (
	"encoding/hex"
	"fmt"
	"hash"
	"io"
)

func Hash(hasher hash.Hash, src io.Reader) (string, error) {
	if _, err := io.Copy(hasher, src); err != nil {
		return "", fmt.Errorf("unable to hash contents: %w", err)
	}

	hashed := hasher.Sum(nil)
	return hex.EncodeToString(hashed), nil
}
