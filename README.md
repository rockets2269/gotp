# gotp
This is a Go package for TOTP authentication.  
- Built in Go version 1.21.4
- Forked [otp](https://github.com/pquerna/otp)
- Uses the [barcode](https://github.com/boombuler/barcode)

## Roadmap
- [X] Handle TOTP authentication
- [X] Handle HOTP authentication

## References about TOTP
https://datatracker.ietf.org/doc/html/rfc6238

- MUST, MUST NOT
  - The prover and verifier must know or be able to derive the current Unix time for OTP generation.
  - The prover and verifier must either share the same secret or the knowledge of a secret transformation to generate a shared secret.
  - The algorithm must use HOTP [RFC4226][] as a key building block.
  - The prover and verifier must use the same time-step value X.
  - There must be a unique secret (key) for each prover.
  - The implementation of this algorithm must support a time value T larger than a 32-bit integer when it is beyond the year 2038.
  - The key store must be in a secure area, to avoid, as possible, direct attack on the validation system and secrets database.
  - The next different OTP must be generated in the next time-step window.
  - A user must wait until the clock moves to the next time-step window from the last submission.
  - The verifier must not accept the second attempt of the OTP after the successful validation has been issued for the firstOTP, 
which ensures one-time only use of an OTP.
- SHOULD, SHOUD NOT
  - The keys should be randomly generated or derived using key derivation algorithms.
  - The keys may be stored in a tamper-resistant device and should be protected against unauthorized access and usage.
  - The keys should be chosen at randome or using a cryptographically strong pseudorandom generator properly seeded with a random value.
  - The keys shoud be of the length of the HMAC output to facilitate interoperability.
  - The pseudorandom numbers used for generationg the keys should successfully pass the randomness test.
  - All the communications should take place over a secure channel, e.g., SSL/TLS or IPsec connections.
  - Access to the key material should be limited to programs and processes required by the validation system only.
  - A validation system should typically set a policy for an acceptable OTP transmisson delay window for validation.
  - The validation system should compare OTPs not only with receiving timestamp but also the past timestamps that are within the 
transmission delay.
  - Additional authentication measures should be used to safely authenticate the prover and explicitly resynchronize the clock drift between
the prover and the validator.




[RFC4226]:  https://datatracker.ietf.org/doc/html/rfc4226  "RFC4226"
