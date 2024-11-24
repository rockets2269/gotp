package hotp

import (
	"crypto/hmac"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/rocketssan/gotp"
)

const debug = false

type ValidateOpts struct {
	Digits    gotp.Digits
	Algorithm gotp.Algorithm
}

func GenerateCode(secret string, counter uint64) (passcode string, err error) {
	return GenerateCodeCustom(secret, counter, ValidateOpts{
		Digits:    gotp.DigitsSix,
		Algorithm: gotp.AlgorithmSHA1,
	})
}

func GenerateCodeCustom(secret string, counter uint64, opts ValidateOpts) (passcode string, err error) {
	if opts.Digits == 0 {
		opts.Digits = gotp.DigitsSix
	}

	secret = strings.TrimSpace(secret)
	if n := len(secret) % 8; n != 0 {
		secret = secret + strings.Repeat("=", 8-n)
	}

	secret = strings.ToUpper(secret)

	secretBytes, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", errors.New("failed to decode")
	}

	buf := make([]byte, 8)
	mac := hmac.New(opts.Algorithm.Hash, secretBytes)
	binary.BigEndian.PutUint64(buf, counter)
	if debug {
		fmt.Printf("counter=%v", counter)
		fmt.Printf("buf=%v", buf)
	}

	mac.Write(buf)
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0xf
	value := int64(((int(sum[offset]) & 0x7f) << 24) |
		((int(sum[offset+1] & 0xff)) << 16) |
		((int(sum[offset+2] & 0xff)) << 8) |
		(int(sum[offset+3]) & 0xff))

	l := opts.Digits.Length()
	mod := int32(value % int64(math.Pow10(l)))

	return opts.Digits.Format(mod), nil
}

func Validate(passcode string, counter uint64, secret string) bool {
	result, _ := ValidateCodeCustom(
		passcode,
		counter,
		secret,
		ValidateOpts{
			Digits:    gotp.DigitsSix,
			Algorithm: gotp.AlgorithmSHA1,
		},
	)

	return result
}

func ValidateCodeCustom(passcode string, counter uint64, secret string, opts ValidateOpts) (result bool, err error) {
	passcode = strings.TrimSpace(passcode)
	if len(passcode) != opts.Digits.Length() {
		return false, errors.New("passcord digits are wrong")
	}

	otpCode, err := GenerateCodeCustom(secret, counter, opts)
	if err != nil {
		return false, err
	}

	if subtle.ConstantTimeCompare([]byte(otpCode), []byte(passcode)) == 1 {
		return true, nil
	}

	return false, nil
}
