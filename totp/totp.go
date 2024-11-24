package totp

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"io"
	"math"
	"net/url"
	"strconv"
	"time"

	"github.com/rocketssan/gotp"
	"github.com/rocketssan/gotp/hotp"
	"github.com/rocketssan/gotp/internal"
)

// ValidateOpts is the type used to handling options of TOTP validate.
type ValidateOpts struct {
	Period    uint
	Window    uint
	Digits    gotp.Digits
	Algorithm gotp.Algorithm
}

// GenerateCode generates and returns passcode.
func GenerateCode(secret string, t time.Time) (passcode string, err error) {
	return GenerateCodeCustom(secret, t, ValidateOpts{
		Period:    30,
		Window:    1,
		Digits:    gotp.DigitsSix,
		Algorithm: gotp.AlgorithmSHA1,
	})
}

func GenerateCodeCustom(secret string, t time.Time, opts ValidateOpts) (passcode string, err error) {
	if opts.Period == 0 {
		opts.Period = 30
	}

	// The implementation of this algorithm must support a time value
	// T larger than a 32-bit integer when it is beyond the year 2038.
	// Read https://datatracker.ietf.org/doc/html/rfc6238#section-4.2
	counter := uint64(float64(t.Unix()) / float64(opts.Period))

	passcode, err = hotp.GenerateCodeCustom(secret, counter, hotp.ValidateOpts{
		Digits:    opts.Digits,
		Algorithm: opts.Algorithm,
	})
	if err != nil {
		return "", err
	}
	return passcode, nil
}

func ValidateCode(passcode string, secret string) bool {
	result, _ := ValidateCodeCustom(
		passcode,
		secret,
		time.Now().UTC(),
		ValidateOpts{
			Period:    30,
			Window:    1,
			Digits:    gotp.DigitsSix,
			Algorithm: gotp.AlgorithmSHA1,
		},
	)

	return result
}

func ValidateCodeCustom(passcode string, secret string, t time.Time, opts ValidateOpts) (result bool, err error) {
	if opts.Period == 0 {
		opts.Period = 30
	}

	// The next different OTP must be generated in the next time-step window.
	// But if window value set, it flows.
	windowsSize := []uint64{}
	counter := int64(math.Floor(float64(t.Unix()) / float64(opts.Period)))

	windowsSize = append(windowsSize, uint64(counter))
	for i := 1; i <= int(opts.Window); i++ {
		windowsSize = append(windowsSize, uint64(counter+int64(i)))
		windowsSize = append(windowsSize, uint64(counter-int64(i)))
	}

	for _, w := range windowsSize {
		result, err := hotp.ValidateCodeCustom(passcode, w, secret, hotp.ValidateOpts{
			Digits:    opts.Digits,
			Algorithm: opts.Algorithm,
		})
		if err != nil {
			return false, err
		}
		if result {
			return true, nil
		}
	}

	return false, nil
}

type GenerateOpts struct {
	Issuer      string
	AccountName string
	Period      uint
	SecretSize  uint
	Secret      []byte
	Digits      gotp.Digits
	Algorithm   gotp.Algorithm
	Rand        io.Reader
}

var b32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)

func GenerateTotpKey(opts GenerateOpts) (key *gotp.Key, err error) {
	if opts.Issuer == "" {
		return nil, errors.New("issuer is must")
	}

	if opts.AccountName == "" {
		return nil, errors.New("account name is must")
	}

	if opts.Period == 0 {
		opts.Period = 30
	}

	if opts.SecretSize == 0 {
		opts.SecretSize = 20
	}

	if opts.Digits == 0 {
		opts.Digits = gotp.DigitsSix
	}

	if opts.Rand == nil {
		opts.Rand = rand.Reader
	}

	v := url.Values{}
	if len(opts.Secret) != 0 {
		v.Set("secret", b32NoPadding.EncodeToString(opts.Secret))
	} else {
		secret := make([]byte, opts.SecretSize)

		_, err := opts.Rand.Read(secret)
		if err != nil {
			return nil, err
		}
		v.Set("secret", b32NoPadding.EncodeToString(secret))
	}

	v.Set("issuer", opts.Issuer)
	v.Set("period", strconv.FormatUint(uint64(opts.Period), 10))
	v.Set("algorithm", opts.Algorithm.String())
	v.Set("digits", opts.Digits.String())

	u := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/" + opts.Issuer + ":" + opts.AccountName,
		RawQuery: internal.EncodeQuery(v),
	}

	return gotp.NewKeyFromURL(u.String())
}
