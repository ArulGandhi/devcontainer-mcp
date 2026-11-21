package oauth

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"slices"
)

const (
	PasswordIterations = 600000
	MinPasswordBytes   = 12
	GeminiRedirectURI  = "https://vertexaisearch.cloud.google.com/oauth-redirect"
)

// AuthFile is the single operator's login plus the one pre-registered OAuth client.
type AuthFile struct {
	PasswordSalt     []byte   `json:"password_salt"`
	PasswordIter     int      `json:"password_iter"`
	PasswordHash     []byte   `json:"password_hash"`
	TOTPSecret       []byte   `json:"totp_secret"`
	SigningKey       []byte   `json:"signing_key"`
	ClientID         string   `json:"client_id"`
	ClientSecretHash []byte   `json:"client_secret_hash"`
	RedirectURIs     []string `json:"redirect_uris"`
}

func NewAuthFile(password string) (AuthFile, error) {
	if len(password) < MinPasswordBytes {
		return AuthFile{}, fmt.Errorf("password must be at least %d bytes", MinPasswordBytes)
	}
	salt, err := randomBytes(16)
	if err != nil {
		return AuthFile{}, err
	}
	hash, err := pbkdf2.Key(sha256.New, password, salt, PasswordIterations, 32)
	if err != nil {
		return AuthFile{}, fmt.Errorf("hash password: %w", err)
	}
	totpSecret, err := randomBytes(20)
	if err != nil {
		return AuthFile{}, err
	}
	signingKey, err := randomBytes(32)
	if err != nil {
		return AuthFile{}, err
	}
	return AuthFile{
		PasswordSalt: salt,
		PasswordIter: PasswordIterations,
		PasswordHash: hash,
		TOTPSecret:   totpSecret,
		SigningKey:   signingKey,
	}, nil
}

// WithClient issues the client ID and secret pair. The secret is returned once; only its hash is kept.
func (a AuthFile) WithClient(redirectURIs []string) (AuthFile, string, string, error) {
	if len(redirectURIs) == 0 {
		return AuthFile{}, "", "", errors.New("at least one redirect URI is required")
	}
	for _, uri := range redirectURIs {
		if !validRedirectURI(uri) {
			return AuthFile{}, "", "", fmt.Errorf("redirect URI %q must be https, or http on a loopback host, with no fragment", uri)
		}
	}
	id, err := randomBytes(16)
	if err != nil {
		return AuthFile{}, "", "", err
	}
	secretBytes, err := randomBytes(32)
	if err != nil {
		return AuthFile{}, "", "", err
	}
	clientID := base64.RawURLEncoding.EncodeToString(id)
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)
	sum := sha256.Sum256([]byte(secret))
	a.ClientID = clientID
	a.ClientSecretHash = sum[:]
	a.RedirectURIs = slices.Clone(redirectURIs)
	return a, clientID, secret, nil
}

// Validate checks everything the server needs, including the pre-registered client.
func (a AuthFile) Validate() error {
	if err := a.validateLogin(); err != nil {
		return err
	}
	switch {
	case a.ClientID == "" || len(a.ClientSecretHash) != sha256.Size:
		return errors.New("auth file has no client credentials; run issue-client")
	case len(a.RedirectURIs) == 0:
		return errors.New("auth file has no redirect URIs; run issue-client")
	}
	return nil
}

func (a AuthFile) validateLogin() error {
	switch {
	case len(a.PasswordSalt) == 0, len(a.PasswordHash) == 0:
		return errors.New("auth file has no password")
	case a.PasswordIter < PasswordIterations:
		return fmt.Errorf("auth file password iterations %d are below %d", a.PasswordIter, PasswordIterations)
	case len(a.TOTPSecret) < 16:
		return errors.New("auth file has no TOTP secret")
	case len(a.SigningKey) < 32:
		return errors.New("auth file has no signing key")
	}
	return nil
}

func (a AuthFile) CheckPassword(password string) bool {
	got, err := pbkdf2.Key(sha256.New, password, a.PasswordSalt, a.PasswordIter, len(a.PasswordHash))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, a.PasswordHash) == 1
}

func (a AuthFile) CheckClient(clientID, secret string) bool {
	sum := sha256.Sum256([]byte(secret))
	return subtle.ConstantTimeCompare([]byte(clientID), []byte(a.ClientID)) == 1 &&
		subtle.ConstantTimeCompare(sum[:], a.ClientSecretHash) == 1
}

// OTPAuthURI is what an authenticator app imports.
func (a AuthFile) OTPAuthURI(issuer, account string) string {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(a.TOTPSecret)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" + q.Encode()
}

func LoadAuthFile(path string) (AuthFile, error) {
	info, err := os.Stat(path)
	if err != nil {
		return AuthFile{}, fmt.Errorf("auth file: %w", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return AuthFile{}, fmt.Errorf("auth file %s is accessible to group or others (mode %o); run chmod 600", path, perm)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return AuthFile{}, fmt.Errorf("auth file: %w", err)
	}
	var a AuthFile
	if err := json.Unmarshal(raw, &a); err != nil {
		return AuthFile{}, fmt.Errorf("auth file %s: %w", path, err)
	}
	if err := a.validateLogin(); err != nil {
		return AuthFile{}, err
	}
	return a, nil
}

func SaveAuthFile(path string, a AuthFile) error {
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return fmt.Errorf("encode auth file: %w", err)
	}
	return writeSecretFile(path, data)
}

func validRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Fragment != "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		return isLoopbackHost(u.Hostname())
	}
	return false
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("random: %w", err)
	}
	return b, nil
}
