package iris_security_util

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"github.com/pelletier/go-toml"
	"log"
	"strings"
)

func Base64Encode(str string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(str))
}

func HS256(str string, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(str))
	sum := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func HS384(str string, key string) string {
	mac := hmac.New(sha512.New384, []byte(key))
	mac.Write([]byte(str))
	sum := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func HS512(str string, key string) string {
	mac := hmac.New(sha512.New, []byte(key))
	mac.Write([]byte(str))
	sum := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func Base64Decode(str string) string {
	base64Encoding := base64.RawURLEncoding
	if strings.ContainsAny(str, "+/") {
		base64Encoding = base64.RawStdEncoding
	}
	if strings.HasSuffix(str, "=") {
		str = strings.TrimRight(str, "=")
	}
	data, err := base64Encoding.DecodeString(str)
	if err != nil {
		log.Println(err)
	}
	return string(data)
}
func Sha256(str string) string {
	sum := sha256.Sum256([]byte(str))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func Sha384(str string) string {
	sum := sha512.Sum384([]byte(str))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func Sha512(str string) string {
	sum := sha512.Sum512([]byte(str))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
func Hash(str string, config *toml.Tree, flag bool) string {
	hash := strings.ToUpper(GetString(config, "hash", "SHA256"))
	if flag && GetBool(config, "use-hmac-hash") {
		key := GetString(config, "key")
		if key != "" {
			switch hash {
			case "SHA256":
				return HS256(str, key)
			case "SHA384":
				return HS384(str, key)
			case "SHA512":
				return HS512(str, key)
			default:
				return HS256(str, key)
			}
		}
	}
	switch hash {
	case "SHA256":
		return Sha256(str)
	case "SHA384":
		return Sha384(str)
	case "SHA512":
		return Sha512(str)
	default:
		return Sha256(str)
	}
}
