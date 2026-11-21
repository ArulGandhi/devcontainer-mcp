package oauth

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"time"
)

const (
	totpPeriod = 30
	totpDigits = 1000000
)

// totpCode implements RFC 6238 (HMAC-SHA1, 6 digits, 30 second steps), the default every authenticator app uses.
func totpCode(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[off]&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])) % totpDigits
	return fmt.Sprintf("%06d", code)
}

// verifyTOTP accepts the current step and one step either side (clock drift), and never a step at or before lastStep.
func verifyTOTP(secret []byte, code string, now time.Time, lastStep int64) (int64, bool) {
	current := now.Unix() / totpPeriod
	for step := current - 1; step <= current+1; step++ {
		if step <= lastStep {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(totpCode(secret, step)), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}
