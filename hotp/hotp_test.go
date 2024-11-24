package hotp

import (
	"encoding/base32"
	"fmt"
	"testing"
)

func TestGenerateCode(t *testing.T) {
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	code, err := GenerateCodeCustom("foo", 1, ValidateOpts{})
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println(code)

	code, err = GenerateCodeCustom(secSha1, 1, ValidateOpts{})
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println(code)
}
