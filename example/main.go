package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"image/png"
	"os"

	"github.com/rocketssan/gotp/totp"
)

var (
	keyDir         string = "./qrcode"
	pngFilePath    string = fmt.Sprintf("%s/code.png", keyDir)
	secretFilePath string = fmt.Sprintf("%s/secret.txt", keyDir)
	Issuer         string
	AccountName    string
)

func init() {
	Issuer = *flag.String("issuer", "gotp.test", "Issuer")
	AccountName = *flag.String("account", "example@gotp.test", "Account Name")

	flag.Parse()
}

func main() {
	fmt.Println("")

	if _, err := os.Stat(keyDir); err != nil {
		fmt.Println("Key directory not found, start to create it.")

		err := os.Mkdir(keyDir, os.ModePerm)
		if err != nil {
			panic(err)
		}
	}

	fmt.Println("")

	if _, err := os.Stat(pngFilePath); err != nil {
		fmt.Println("QR code file not found, start to create keys.")
		createKey()
		os.Exit(0)
	}
	if _, err := os.Stat(secretFilePath); err != nil {
		fmt.Println("Secret file not found, start to create keys.")
		createKey()
		os.Exit(0)
	}

	b, err := os.ReadFile(secretFilePath)
	if err != nil {
		panic(err)
	}

	secret := string(b)
	fmt.Printf("Secret is %v\n", secret)
	valid(secret)
}

func createKey() {
	key, err := totp.GenerateTotpKey(totp.GenerateOpts{
		Issuer:      Issuer,
		AccountName: AccountName,
	})
	if err != nil {
		panic(err)
	}

	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		panic(err)
	}
	png.Encode(&buf, img)

	fmt.Println("")
	fmt.Println("---------------------------")
	fmt.Printf("Issuer:       %s\n", key.Issuer())
	fmt.Printf("Account Name: %s\n", key.AccountName())
	fmt.Printf("Secret:       %s\n", key.Secret())
	fmt.Println("---------------------------")
	fmt.Println("")

	fmt.Printf("Writing PNG to %s...\n", pngFilePath)
	os.WriteFile(pngFilePath, buf.Bytes(), 0644)

	fmt.Printf("Writing secret to %s...\n", secretFilePath)
	err = os.WriteFile(secretFilePath, []byte(key.Secret()), os.ModePerm)
	if err != nil {
		panic(err)
	}

	fmt.Println("")
	fmt.Println("Please add created TOTP to your OTP Application, and execute this again!")
	fmt.Println("")
}

func valid(secret string) {
	fmt.Println("")
	fmt.Println("Validating TOTP...")

	fmt.Print("Enter Passcode: ")
	reader := bufio.NewReader(os.Stdin)
	passcode, err := reader.ReadString('\n')
	if err != nil {
		panic(err)
	}

	println("")
	println("")

	valid := totp.ValidateCode(passcode, secret)
	if valid {
		println("Valid passcode!")
		println("")
	} else {
		println("Failed to valid passcode...")
		println("")
		os.Exit(1)
	}
}
