package security

import (
	"crypto/sha256"
	lcrypt "github.com/analogj/go-lastpass/security/crypt"
	"golang.org/x/crypto/pbkdf2"

)
func MakeKey(username, password string, iterationCount int) []byte {
	if iterationCount == 1 {
		b := sha256.Sum256([]byte(username + password))
		return b[:]
	}
	return pbkdf2.Key([]byte(password), []byte(username), iterationCount, 32, sha256.New)
}

func MakeHash(username, password string, iterationCount int) []byte {
	key := MakeKey(username, password, iterationCount)
	if iterationCount == 1 {
		b := sha256.Sum256([]byte(string(lcrypt.EncodeHex(key)) + password))
		return lcrypt.EncodeHex(b[:])
	}
	return lcrypt.EncodeHex(pbkdf2.Key([]byte(key), []byte(password), 1, 32, sha256.New))
}