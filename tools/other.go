package tools

import "encoding/base64"

// UnBase64 Is Func
func UnBase64(data string) (result []byte) {
	result, err := base64.StdEncoding.DecodeString(data)
	CheckError(err)
	return
}
