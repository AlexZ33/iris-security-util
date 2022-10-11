package iris_security_util

import "encoding/base64"

func Base64Encode(str string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(str))
}
