package gotp

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"image"
	"net/url"
	"strings"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
)

type Digits int

const (
	DigitsSix   Digits = 6
	DigitsEight Digits = 8
)

func (d Digits) Length() int {
	return int(d)
}

func (d Digits) Format(i int32) string {
	f := fmt.Sprintf("%%0%dd", d)
	return fmt.Sprintf(f, i)
}

func (d Digits) String() string {
	return fmt.Sprintf("%d", d)
}

type Algorithm int

const (
	AlgorithmSHA1 Algorithm = iota
	AlgorithmSHA256
	AlgorithmSHA512
	AlgorithmMD5
)

// Hash returns the hash of the algorithm, it does panic if the algorithm is unknown.
func (a Algorithm) Hash() hash.Hash {
	switch a {
	case AlgorithmSHA1:
		return sha1.New()
	case AlgorithmSHA256:
		return sha256.New()
	case AlgorithmSHA512:
		return sha512.New()
	case AlgorithmMD5:
		return md5.New()
	}

	panic("Unreached hash.")
}

// String returns Algorithm string.
func (a Algorithm) String() string {
	switch a {
	case AlgorithmSHA1:
		return "SHA1"
	case AlgorithmSHA256:
		return "SHA256"
	case AlgorithmSHA512:
		return "SHA512"
	case AlgorithmMD5:
		return "MD5"
	}

	panic("Unreached string.")
}

type Key struct {
	origin string
	url    *url.URL
}

// Image creates and returns a QR code image.
func (k *Key) Image(width int, height int) (img image.Image, err error) {
	b, err := qr.Encode(k.origin, qr.M, qr.Auto)
	if err != nil {
		return nil, err
	}

	b, err = barcode.Scale(b, width, height)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// Issuer gets the issuer from URL query.
func (k *Key) Issuer() string {
	q := k.url.Query()

	issuer := q.Get("issuer")

	if issuer != "" {
		return issuer
	}

	p := strings.TrimPrefix(k.url.Path, "/")
	i := strings.Index(p, ":")

	if i == -1 {
		return ""
	}

	return p[:i]
}

// Issuer gets the account name from URL.
func (k *Key) AccountName() string {
	p := strings.TrimPrefix(k.url.Path, "/")
	i := strings.Index(p, ":")

	if i == -1 {
		return p
	}

	return p[i+1:]
}

// Issuer gets the secret from URL query.
func (k *Key) Secret() string {
	q := k.url.Query()

	return q.Get("secret")
}

// NewKeyFromURL creates new Key from URL.
func NewKeyFromURL(origin string) (key *Key, err error) {
	s := strings.TrimSpace(origin)

	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}

	return &Key{
		origin: s,
		url:    u,
	}, nil
}
