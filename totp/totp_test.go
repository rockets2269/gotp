package totp

import (
	"encoding/base32"
	"fmt"
	"testing"
	"time"

	"github.com/rocketssan/gotp"
)

type tc struct {
	TS     int64
	TOTP   string
	Mode   gotp.Algorithm
	Secret string
}

var (
	secSha1   = base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	secSha256 = base32.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	secSha512 = base32.StdEncoding.EncodeToString([]byte("1234567890123456789012345678901234567890123456789012345678901234"))

	rfcMatrixTCs = []tc{
		{59, "94287082", gotp.AlgorithmSHA1, secSha1},
		{59, "46119246", gotp.AlgorithmSHA256, secSha256},
		{59, "90693936", gotp.AlgorithmSHA512, secSha512},
		{1111111109, "07081804", gotp.AlgorithmSHA1, secSha1},
		{1111111109, "68084774", gotp.AlgorithmSHA256, secSha256},
		{1111111109, "25091201", gotp.AlgorithmSHA512, secSha512},
		{1111111111, "14050471", gotp.AlgorithmSHA1, secSha1},
		{1111111111, "67062674", gotp.AlgorithmSHA256, secSha256},
		{1111111111, "99943326", gotp.AlgorithmSHA512, secSha512},
		{1234567890, "89005924", gotp.AlgorithmSHA1, secSha1},
		{1234567890, "91819424", gotp.AlgorithmSHA256, secSha256},
		{1234567890, "93441116", gotp.AlgorithmSHA512, secSha512},
		{2000000000, "69279037", gotp.AlgorithmSHA1, secSha1},
		{2000000000, "90698825", gotp.AlgorithmSHA256, secSha256},
		{2000000000, "38618901", gotp.AlgorithmSHA512, secSha512},
		{20000000000, "65353130", gotp.AlgorithmSHA1, secSha1},
		{20000000000, "77737706", gotp.AlgorithmSHA256, secSha256},
		{20000000000, "47863826", gotp.AlgorithmSHA512, secSha512},
	}
)

func TestValidateRFCMatrix(t *testing.T) {
	for _, tx := range rfcMatrixTCs {
		valid, err := ValidateCodeCustom(tx.TOTP, tx.Secret, time.Unix(tx.TS, 0).UTC(),
			ValidateOpts{
				Digits:    gotp.DigitsEight,
				Algorithm: tx.Mode,
			},
		)

		if err != nil {
			fmt.Printf("unexpected error totp=%s mode=%v ts=%v\n", tx.TOTP, tx.Mode, tx.TS)
			continue
		}
		if valid == false {
			fmt.Printf("unexpected totp failure totp=%s mode=%v ts=%v\n", tx.TOTP, tx.Mode, tx.TS)
			continue
		}

		fmt.Printf("validate succeed totp=%s mode=%v ts=%v\n", tx.TOTP, tx.Mode, tx.TS)
	}
}

func TestGenerateRFCTCs(t *testing.T) {
	for _, tx := range rfcMatrixTCs {
		passcode, err := GenerateCodeCustom(tx.Secret, time.Unix(tx.TS, 0).UTC(),
			ValidateOpts{
				Digits:    gotp.DigitsEight,
				Algorithm: tx.Mode,
			},
		)
		if err != nil {
			fmt.Printf("unexpected error totp=%s mode=%v ts=%v\n", tx.TOTP, tx.Mode, tx.TS)
		}
		fmt.Printf("Created passcode. totp=%s mode=%v ts=%v passcode:=%v\n", tx.TOTP, tx.Mode, tx.TS, passcode)
	}
}

var issuer = "gotp.test"
var correctAcountName = "gotp@gotp.test"

func TestGenerateTotpKey(t *testing.T) {
	k, err := GenerateTotpKey(GenerateOpts{
		Issuer:      issuer,
		AccountName: correctAcountName,
	})
	if err != nil {
		t.Errorf("faied to generate totp key. %v", err)
	} else {
		fmt.Println(k)
	}

	k, err = GenerateTotpKey(GenerateOpts{
		Issuer:      issuer,
		AccountName: correctAcountName,
	})
	if err != nil {
		t.Errorf("failed to generate TOTP key; %v", err)
	} else {
		fmt.Println(k)
	}
}
