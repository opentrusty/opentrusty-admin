package config

import "encoding/hex"

// DecodeSecret attempts to decode a hex-encoded secret (e.g. from openssl rand -hex 32 or od).
// If the string is not valid hex, it returns the raw bytes, allowing backwards compatibility
// with plaintext secrets.
func DecodeSecret(secret string) []byte {
	decoded, err := hex.DecodeString(secret)
	if err == nil && len(decoded) > 0 {
		return decoded
	}
	return []byte(secret)
}
