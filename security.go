package iris_security_util

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"github.com/google/uuid"
	"log"
)

func Id() string {
	id, err := uuid.NewRandom()
	if err != nil {
		log.Println(err)
	}
	return id.String()
}

func CheckId(s string) bool {
	if _, err := uuid.Parse(s); err != nil {
		log.Println(err)
		return false
	}
	return true
}

func Key(phrase string) string {
	return HS256(phrase, Base64Encode(phrase))
}

func HS256(str string, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(str))
	sum := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
