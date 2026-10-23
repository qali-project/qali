package domain

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // G505: RFC 6238 TOTP is defined over HMAC-SHA-1 (ADR-0006)
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"time"
)

const (
	totpPeriod  = 30
	totpDigits  = 6
	totpModulus = 1_000_000
	totpSkew    = 1
	secretBytes = 20
)

var totpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns 160 random bits.
func NewTOTPSecret() []byte {
	b := make([]byte, secretBytes)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error
	return b
}

// EncodeTOTPSecret returns the base32 form authenticator apps expect.
func EncodeTOTPSecret(secret []byte) string { return totpEncoding.EncodeToString(secret) }

// TOTPStep returns the 30-second time step containing t.
func TOTPStep(t time.Time) int64 { return t.Unix() / totpPeriod }

// TOTPCode returns the 6-digit code for a step (RFC 4226 / RFC 6238, SHA-1).
func TOTPCode(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) //nolint:gosec // G115: steps are non-negative
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, value%totpModulus)
}

// VerifyTOTP accepts a code for the current step or one step either side, if
// that step is newer than lastStep (replay protection). It returns the
// matched step to store as the new lastStep.
func VerifyTOTP(secret []byte, code string, now time.Time, lastStep int64) (int64, bool) {
	if len(code) != totpDigits {
		return 0, false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	current := TOTPStep(now)
	matched, ok := int64(0), false
	for offset := int64(-totpSkew); offset <= totpSkew; offset++ {
		step := current + offset
		equal := subtle.ConstantTimeCompare([]byte(TOTPCode(secret, step)), []byte(code)) == 1
		if equal && step > lastStep && !ok {
			matched, ok = step, true
		}
	}
	return matched, ok
}

// TOTPURI builds the otpauth:// URI for authenticator apps.
func TOTPURI(issuer, account string, secret []byte) string {
	q := url.Values{}
	q.Set("secret", EncodeTOTPSecret(secret))
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	u := url.URL{Scheme: "otpauth", Host: "totp", Path: "/" + issuer + ":" + account, RawQuery: q.Encode()}
	return u.String()
}
