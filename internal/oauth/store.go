package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const maxDynamicClients = 50

var errInvalidGrant = errors.New("invalid grant")

// Client is a dynamically registered client. Public clients have no secret and rely on PKCE;
// confidential clients (client_secret_basic or client_secret_post) get a secret that is stored only as a hash.
type Client struct {
	ID           string   `json:"id"`
	Name         string   `json:"name,omitempty"`
	RedirectURIs []string `json:"redirect_uris"`
	IssuedAt     int64    `json:"issued_at"`
	// SecretHash is set for confidential dynamic clients; public clients (method none) leave it empty.
	SecretHash []byte `json:"secret_hash,omitempty"`
}

type tokenRecord struct {
	ClientID  string    `json:"client_id"`
	Resource  string    `json:"resource"`
	ExpiresAt time.Time `json:"expires_at"`
}

type storeState struct {
	Clients      map[string]Client      `json:"clients"`
	Access       map[string]tokenRecord `json:"access"`
	Refresh      map[string]tokenRecord `json:"refresh"`
	LastTOTPStep int64                  `json:"last_totp_step"`
}

// Store persists dynamic clients, hashed tokens and the last TOTP step, so a restart doesn't log anyone out.
// Raw tokens are never written.
type Store struct {
	mu   sync.Mutex
	path string
	st   storeState
}

func OpenStore(path string) (*Store, error) {
	s := &Store{path: path}
	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("read state: %w", err)
	default:
		if err := json.Unmarshal(raw, &s.st); err != nil {
			return nil, fmt.Errorf("state file %s: %w", path, err)
		}
	}
	if s.st.Clients == nil {
		s.st.Clients = map[string]Client{}
	}
	if s.st.Access == nil {
		s.st.Access = map[string]tokenRecord{}
	}
	if s.st.Refresh == nil {
		s.st.Refresh = map[string]tokenRecord{}
	}
	return s, nil
}

func (s *Store) saveLocked() error {
	data, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	return writeSecretFile(s.path, data)
}

func (s *Store) AddClient(c Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.st.Clients) >= maxDynamicClients {
		return fmt.Errorf("client registration limit of %d reached", maxDynamicClients)
	}
	s.st.Clients[c.ID] = c
	return s.saveLocked()
}

func (s *Store) Client(id string) (Client, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.st.Clients[id]
	return c, ok
}

func (s *Store) IssueTokens(clientID, resource string, now time.Time, accessTTL, refreshTTL time.Duration) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.issueLocked(clientID, resource, now, accessTTL, refreshTTL)
}

func (s *Store) issueLocked(clientID, resource string, now time.Time, accessTTL, refreshTTL time.Duration) (string, string, error) {
	access, err := newToken()
	if err != nil {
		return "", "", err
	}
	refresh, err := newToken()
	if err != nil {
		return "", "", err
	}
	s.pruneLocked(now)
	s.st.Access[hashToken(access)] = tokenRecord{ClientID: clientID, Resource: resource, ExpiresAt: now.Add(accessTTL)}
	s.st.Refresh[hashToken(refresh)] = tokenRecord{ClientID: clientID, Resource: resource, ExpiresAt: now.Add(refreshTTL)}
	if err := s.saveLocked(); err != nil {
		return "", "", err
	}
	return access, refresh, nil
}

func (s *Store) ValidAccess(token, resource string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.st.Access[hashToken(token)]
	return ok && now.Before(rec.ExpiresAt) && rec.Resource == resource
}

// RotateRefresh spends a refresh token and issues a new pair. A refresh token works once.
func (s *Store) RotateRefresh(token, clientID, resource string, now time.Time, accessTTL, refreshTTL time.Duration) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := hashToken(token)
	rec, ok := s.st.Refresh[h]
	if !ok || !now.Before(rec.ExpiresAt) || rec.ClientID != clientID || rec.Resource != resource {
		return "", "", errInvalidGrant
	}
	delete(s.st.Refresh, h)
	return s.issueLocked(clientID, resource, now, accessTTL, refreshTTL)
}

func (s *Store) TOTPStep() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.LastTOTPStep
}

func (s *Store) SetTOTPStep(step int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.LastTOTPStep = step
	return s.saveLocked()
}

func (s *Store) pruneLocked(now time.Time) {
	for h, rec := range s.st.Access {
		if !now.Before(rec.ExpiresAt) {
			delete(s.st.Access, h)
		}
	}
	for h, rec := range s.st.Refresh {
		if !now.Before(rec.ExpiresAt) {
			delete(s.st.Refresh, h)
		}
	}
}

func newToken() (string, error) {
	b, err := randomBytes(32)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func writeSecretFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}
