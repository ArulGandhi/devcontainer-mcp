package oauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	accessTTL       = time.Hour
	refreshTTL      = 30 * 24 * time.Hour
	codeTTL         = 5 * time.Minute
	ticketTTL       = 10 * time.Minute
	maxFailures     = 5
	lockoutDuration = 15 * time.Minute
	maxFormBody     = 16 << 10
)

type Config struct {
	PublicURL string
	Auth      AuthFile
	Store     *Store
	Logger    *slog.Logger
	Now       func() time.Time
}

type Server struct {
	cfg      Config
	resource string

	mu          sync.Mutex
	codes       map[string]authCode
	failures    int
	lockedUntil time.Time
}

type authCode struct {
	clientID    string
	redirectURI string
	challenge   string
	resource    string
	expires     time.Time
}

type authParams struct {
	clientID    string
	redirectURI string
	challenge   string
	resource    string
	state       string
}

func New(cfg Config) (*Server, error) {
	if cfg.Store == nil {
		return nil, errors.New("store is nil")
	}
	if cfg.Logger == nil {
		return nil, errors.New("logger is nil")
	}
	if err := cfg.Auth.Validate(); err != nil {
		return nil, err
	}
	pub, err := url.Parse(cfg.PublicURL)
	if err != nil || pub.Host == "" || pub.Path != "" && pub.Path != "/" || pub.RawQuery != "" || pub.Fragment != "" {
		return nil, fmt.Errorf("public URL %q must be an origin like https://host", cfg.PublicURL)
	}
	if pub.Scheme != "https" && !(pub.Scheme == "http" && isLoopbackHost(pub.Hostname())) {
		return nil, fmt.Errorf("public URL %q must use https", cfg.PublicURL)
	}
	cfg.PublicURL = pub.Scheme + "://" + pub.Host
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Server{
		cfg:      cfg,
		resource: cfg.PublicURL + "/mcp",
		codes:    map[string]authCode{},
	}, nil
}

func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", s.protectedResourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.authServerMetadata)
	mux.HandleFunc("POST /register", s.register)
	mux.HandleFunc("GET /authorize", s.authorizeForm)
	mux.HandleFunc("POST /authorize", s.authorizeSubmit)
	mux.HandleFunc("POST /token", s.token)
}

// RequireToken lets a request through only with a live access token issued for this resource.
func (s *Server) RequireToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, present := bearerToken(r)
		switch {
		case !present:
			s.challenge(w, "")
		case !s.cfg.Store.ValidAccess(token, s.resource, s.cfg.Now()):
			s.challenge(w, "invalid_token")
		default:
			next.ServeHTTP(w, r)
		}
	})
}

// refuse logs why a token request failed (never the secrets themselves) and answers with the OAuth error.
func (s *Server) refuse(w http.ResponseWriter, grant string, status int, code, desc string) {
	s.cfg.Logger.Warn("token request refused", "grant", grant, "status", status, "error", code, "reason", desc)
	oauthError(w, status, code, desc)
}

func (s *Server) challenge(w http.ResponseWriter, errCode string) {
	s.cfg.Logger.Warn("mcp request unauthorized", "error", errCode)
	value := fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, s.cfg.PublicURL)
	if errCode != "" {
		value += fmt.Sprintf(`, error="%s"`, errCode)
	}
	w.Header().Set("WWW-Authenticate", value)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func bearerToken(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return "", false
	}
	return token, true
}

func (s *Server) protectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 s.resource,
		"authorization_servers":    []string{s.cfg.PublicURL},
		"bearer_methods_supported": []string{"header"},
	})
}

func (s *Server) authServerMetadata(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                s.cfg.PublicURL,
		"authorization_endpoint":                s.cfg.PublicURL + "/authorize",
		"token_endpoint":                        s.cfg.PublicURL + "/token",
		"registration_endpoint":                 s.cfg.PublicURL + "/register",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_basic", "client_secret_post"},
	})
}

// redirectURIsFor returns the redirect URIs of the pre-registered client or of a dynamically registered one.
func (s *Server) redirectURIsFor(clientID string) ([]string, bool) {
	if clientID == "" {
		return nil, false
	}
	if subtle.ConstantTimeCompare([]byte(clientID), []byte(s.cfg.Auth.ClientID)) == 1 {
		return s.cfg.Auth.RedirectURIs, true
	}
	if c, ok := s.cfg.Store.Client(clientID); ok {
		return c.RedirectURIs, true
	}
	return nil, false
}

func (s *Server) validateAuth(q url.Values) (authParams, error) {
	if q.Get("response_type") != "code" {
		return authParams{}, errors.New("response_type must be code")
	}
	clientID := q.Get("client_id")
	redirects, ok := s.redirectURIsFor(clientID)
	if !ok {
		return authParams{}, errors.New("unknown client_id")
	}
	redirect := q.Get("redirect_uri")
	if !slices.Contains(redirects, redirect) {
		return authParams{}, errors.New("redirect_uri is not registered for this client")
	}
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		return authParams{}, errors.New("PKCE with code_challenge_method S256 is required")
	}
	if q.Get("resource") != s.resource {
		return authParams{}, fmt.Errorf("resource must be %s", s.resource)
	}
	return authParams{
		clientID:    clientID,
		redirectURI: redirect,
		challenge:   q.Get("code_challenge"),
		resource:    s.resource,
		state:       q.Get("state"),
	}, nil
}

var loginPage = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in</title>
<style>body{font-family:system-ui,sans-serif;max-width:360px;margin:4rem auto;padding:0 1rem}
input{width:100%;padding:.6rem;margin:.3rem 0 1rem;box-sizing:border-box;font-size:1rem}
button{padding:.6rem 1.2rem;font-size:1rem}.err{color:#b00020}</style>
</head><body>
<h1>devcontainer-mcp</h1>
<p>Sign in to authorize this client.</p>
{{if .Error}}<p class="err">{{.Error}}</p>{{end}}
<form method="post" action="/authorize" autocomplete="off">
<input type="hidden" name="ticket" value="{{.Ticket}}">
<label>Password<input type="password" name="password" required autofocus></label>
<label>Authenticator code<input type="text" name="totp" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required></label>
<button type="submit">Sign in</button>
</form></body></html>`))

func (s *Server) authorizeForm(w http.ResponseWriter, r *http.Request) {
	if _, err := s.validateAuth(r.URL.Query()); err != nil {
		http.Error(w, "invalid authorization request: "+err.Error(), http.StatusBadRequest)
		return
	}
	ticket := s.sealTicket(r.URL.RawQuery, s.cfg.Now().Add(ticketTTL))
	s.renderLogin(w, http.StatusOK, ticket, "")
}

func (s *Server) authorizeSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	ticket := r.PostFormValue("ticket")
	q, err := s.openTicket(ticket)
	if err != nil {
		http.Error(w, "login form expired; start the authorization again", http.StatusBadRequest)
		return
	}
	params, err := s.validateAuth(q)
	if err != nil {
		http.Error(w, "invalid authorization request: "+err.Error(), http.StatusBadRequest)
		return
	}
	now := s.cfg.Now()
	if s.locked(now) {
		s.renderLogin(w, http.StatusTooManyRequests, ticket, "Too many failed attempts. Wait a few minutes and try again.")
		return
	}
	if !s.checkLogin(r.PostFormValue("password"), r.PostFormValue("totp"), now) {
		s.recordFailure(now)
		s.cfg.Logger.Warn("login failed", "remote", r.RemoteAddr)
		s.renderLogin(w, http.StatusUnauthorized, ticket, "Wrong password or authenticator code.")
		return
	}
	s.resetFailures()
	s.cfg.Logger.Info("login ok")
	code, err := s.issueCode(params, now)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	u, err := url.Parse(params.redirectURI)
	if err != nil {
		http.Error(w, "bad redirect URI", http.StatusBadRequest)
		return
	}
	qv := u.Query()
	qv.Set("code", code)
	if params.state != "" {
		qv.Set("state", params.state)
	}
	u.RawQuery = qv.Encode()
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Server) renderLogin(w http.ResponseWriter, status int, ticket, msg string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if err := loginPage.Execute(w, map[string]string{"Ticket": ticket, "Error": msg}); err != nil {
		s.cfg.Logger.Error("render login", "error", err)
	}
}

// checkLogin always evaluates both factors so a wrong password doesn't skip the TOTP check.
func (s *Server) checkLogin(password, code string, now time.Time) bool {
	passwordOK := s.cfg.Auth.CheckPassword(password)
	step, totpOK := verifyTOTP(s.cfg.Auth.TOTPSecret, code, now, s.cfg.Store.TOTPStep())
	if !passwordOK || !totpOK {
		return false
	}
	if err := s.cfg.Store.SetTOTPStep(step); err != nil {
		s.cfg.Logger.Error("save totp step", "error", err)
		return false
	}
	return true
}

func (s *Server) locked(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return now.Before(s.lockedUntil)
}

func (s *Server) recordFailure(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures++
	if s.failures >= maxFailures {
		s.failures = 0
		s.lockedUntil = now.Add(lockoutDuration)
	}
}

func (s *Server) resetFailures() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures = 0
}

func (s *Server) issueCode(p authParams, now time.Time) (string, error) {
	code, err := newToken()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for c, ac := range s.codes {
		if !now.Before(ac.expires) {
			delete(s.codes, c)
		}
	}
	s.codes[code] = authCode{
		clientID:    p.clientID,
		redirectURI: p.redirectURI,
		challenge:   p.challenge,
		resource:    p.resource,
		expires:     now.Add(codeTTL),
	}
	return code, nil
}

func (s *Server) takeCode(code string) (authCode, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ac, ok := s.codes[code]
	delete(s.codes, code)
	return ac, ok
}

func (s *Server) sealTicket(rawQuery string, expires time.Time) string {
	payload := []byte(strconv.FormatInt(expires.Unix(), 10) + "|" + rawQuery)
	mac := hmac.New(sha256.New, s.cfg.Auth.SigningKey)
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *Server) openTicket(ticket string) (url.Values, error) {
	body, sig, ok := strings.Cut(ticket, ".")
	if !ok {
		return nil, errors.New("malformed ticket")
	}
	payload, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return nil, errors.New("malformed ticket")
	}
	gotSig, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return nil, errors.New("malformed ticket")
	}
	mac := hmac.New(sha256.New, s.cfg.Auth.SigningKey)
	mac.Write(payload)
	if !hmac.Equal(mac.Sum(nil), gotSig) {
		return nil, errors.New("bad ticket signature")
	}
	expStr, raw, ok := strings.Cut(string(payload), "|")
	if !ok {
		return nil, errors.New("malformed ticket")
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || !s.cfg.Now().Before(time.Unix(exp, 0)) {
		return nil, errors.New("ticket expired")
	}
	return url.ParseQuery(raw)
}

// clientCredentials reads the client from HTTP Basic (RFC 6749 section 2.3.1) or from the form.
func clientCredentials(r *http.Request) (id, secret string) {
	if basicID, basicSecret, ok := r.BasicAuth(); ok {
		unescapedID, errID := url.QueryUnescape(basicID)
		unescapedSecret, errSecret := url.QueryUnescape(basicSecret)
		if errID == nil && errSecret == nil {
			return unescapedID, unescapedSecret
		}
		return "", ""
	}
	return r.PostFormValue("client_id"), r.PostFormValue("client_secret")
}

// authenticateClient returns the client ID when the request is allowed to use the token endpoint.
// The pre-registered client must present its secret. A dynamically registered client is public and relies on PKCE.
func (s *Server) authenticateClient(r *http.Request) (string, bool) {
	id, secret := clientCredentials(r)
	if id == "" {
		return "", false
	}
	if subtle.ConstantTimeCompare([]byte(id), []byte(s.cfg.Auth.ClientID)) == 1 {
		return id, s.cfg.Auth.CheckClient(id, secret)
	}
	if c, ok := s.cfg.Store.Client(id); ok {
		if len(c.SecretHash) == 0 {
			return id, true
		}
		sum := sha256.Sum256([]byte(secret))
		return id, subtle.ConstantTimeCompare(sum[:], c.SecretHash) == 1
	}
	return "", false
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}
	grant := r.PostFormValue("grant_type")
	clientID, ok := s.authenticateClient(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="devcontainer-mcp"`)
		s.refuse(w, grant, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	switch grant {
	case "authorization_code":
		s.exchangeCode(w, r, clientID)
	case "refresh_token":
		s.refreshToken(w, r, clientID)
	default:
		s.refuse(w, grant, http.StatusBadRequest, "unsupported_grant_type", "use authorization_code or refresh_token")
	}
}

func (s *Server) exchangeCode(w http.ResponseWriter, r *http.Request, clientID string) {
	ac, ok := s.takeCode(r.PostFormValue("code"))
	now := s.cfg.Now()
	if !ok || !now.Before(ac.expires) {
		s.refuse(w, "authorization_code", http.StatusBadRequest, "invalid_grant", "authorization code is unknown, used, or expired")
		return
	}
	if clientID != ac.clientID {
		s.refuse(w, "authorization_code", http.StatusBadRequest, "invalid_grant", "code was issued to another client")
		return
	}
	if r.PostFormValue("redirect_uri") != ac.redirectURI {
		s.refuse(w, "authorization_code", http.StatusBadRequest, "invalid_grant", "redirect_uri does not match the authorization request")
		return
	}
	if res := r.PostFormValue("resource"); res != "" && res != ac.resource {
		s.refuse(w, "authorization_code", http.StatusBadRequest, "invalid_target", "resource does not match the authorization request")
		return
	}
	if !pkceMatches(r.PostFormValue("code_verifier"), ac.challenge) {
		s.refuse(w, "authorization_code", http.StatusBadRequest, "invalid_grant", "PKCE verifier does not match")
		return
	}
	access, refresh, err := s.cfg.Store.IssueTokens(clientID, ac.resource, now, accessTTL, refreshTTL)
	if err != nil {
		s.cfg.Logger.Error("issue tokens", "error", err)
		oauthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	s.writeTokens(w, access, refresh)
}

func (s *Server) refreshToken(w http.ResponseWriter, r *http.Request, clientID string) {
	if res := r.PostFormValue("resource"); res != "" && res != s.resource {
		s.refuse(w, "refresh_token", http.StatusBadRequest, "invalid_target", "resource does not match")
		return
	}
	access, refresh, err := s.cfg.Store.RotateRefresh(r.PostFormValue("refresh_token"), clientID, s.resource, s.cfg.Now(), accessTTL, refreshTTL)
	switch {
	case errors.Is(err, errInvalidGrant):
		s.refuse(w, "refresh_token", http.StatusBadRequest, "invalid_grant", "refresh token is unknown, used, or expired")
		return
	case err != nil:
		s.cfg.Logger.Error("rotate refresh token", "error", err)
		oauthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	s.writeTokens(w, access, refresh)
}

func (s *Server) writeTokens(w http.ResponseWriter, access, refresh string) {
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  access,
		"token_type":    "Bearer",
		"expires_in":    int(accessTTL.Seconds()),
		"refresh_token": refresh,
	})
}

// pkceMatches checks an S256 verifier against its challenge (RFC 7636 verifier length 43 to 128).
func pkceMatches(verifier, challenge string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(challenge)) == 1
}

type registerRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

const (
	maxRedirectURIs = 10
	maxClientName   = 100
	maxRegisterBody = 16 << 10
)

// register is RFC 7591 dynamic client registration. It creates public clients only; PKCE is their protection.
func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	r.Body = http.MaxBytesReader(w, r.Body, maxRegisterBody)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "body must be JSON")
		return
	}
	refuse := func(code, desc string) {
		s.cfg.Logger.Warn("client registration refused", "error", code, "reason", desc,
			"redirect_uris", req.RedirectURIs, "token_endpoint_auth_method", req.TokenEndpointAuthMethod)
		oauthError(w, http.StatusBadRequest, code, desc)
	}
	switch {
	case len(req.RedirectURIs) == 0 || len(req.RedirectURIs) > maxRedirectURIs:
		refuse("invalid_redirect_uri", fmt.Sprintf("give 1 to %d redirect URIs", maxRedirectURIs))
		return
	case !slices.Contains([]string{"", "none", "client_secret_basic", "client_secret_post"}, req.TokenEndpointAuthMethod):
		refuse("invalid_client_metadata", "token_endpoint_auth_method must be none, client_secret_basic or client_secret_post")
		return
	case len(req.ClientName) > maxClientName:
		refuse("invalid_client_metadata", "client_name is too long")
		return
	}
	for _, uri := range req.RedirectURIs {
		if !validRedirectURI(uri) {
			refuse("invalid_redirect_uri", "redirect URIs must be https, or http on localhost, with no fragment")
			return
		}
	}
	id, err := newToken()
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	method := req.TokenEndpointAuthMethod
	if method == "" {
		method = "none"
	}
	now := s.cfg.Now()
	client := Client{ID: id, Name: req.ClientName, RedirectURIs: req.RedirectURIs, IssuedAt: now.Unix()}
	resp := map[string]any{
		"client_id":                  id,
		"client_id_issued_at":        now.Unix(),
		"client_name":                req.ClientName,
		"redirect_uris":              req.RedirectURIs,
		"token_endpoint_auth_method": method,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
	}
	if method != "none" {
		secret, err := newToken()
		if err != nil {
			oauthError(w, http.StatusInternalServerError, "server_error", "")
			return
		}
		sum := sha256.Sum256([]byte(secret))
		client.SecretHash = sum[:]
		resp["client_secret"] = secret
		resp["client_secret_expires_at"] = 0
	}
	if err := s.cfg.Store.AddClient(client); err != nil {
		s.cfg.Logger.Warn("client registration refused", "reason", err.Error())
		oauthError(w, http.StatusForbidden, "access_denied", err.Error())
		return
	}
	s.cfg.Logger.Info("client registered", "client_name", req.ClientName, "auth_method", method, "redirect_uris", req.RedirectURIs)
	writeJSON(w, http.StatusCreated, resp)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	body := map[string]string{"error": code}
	if desc != "" {
		body["error_description"] = desc
	}
	writeJSON(w, status, body)
}
