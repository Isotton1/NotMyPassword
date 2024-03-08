package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"errors"
)

func Encrypt(password, master []byte) (string, error) {
	key32bytes := sha512.Sum512_256(master)

	block, err := aes.NewCipher(key32bytes[:])
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce, err := generateRandomBytes(aesGCM.NonceSize())
	if err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, password, nil)
	return hex.EncodeToString(ciphertext), nil
}

func Decrypt(cipherHex string, key []byte) (string, error) {
	key32bytes := sha512.Sum512_256(key)
	ciphertext, err := hex.DecodeString(cipherHex)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key32bytes[:])
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, encryptedText := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, encryptedText, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func generateRandomBytes(numBytes int) ([]byte, error) {
	randBytes := make([]byte, numBytes)
	_, err := rand.Read(randBytes)
	if err != nil {
		return nil, err
	}
	return randBytes, nil
}
