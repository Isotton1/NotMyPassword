package crypto

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
)

func NewHash(text string) string {
	hash := sha512.Sum512([]byte(text))
	return hex.EncodeToString(hash[:])
}

func GenerateRandomString(numBytes int) (string, error) {
	randBytes := make([]byte, numBytes)
	_, err := rand.Read(randBytes)
	if err != nil {
		return "", err
	}
	return string(randBytes), nil
}
