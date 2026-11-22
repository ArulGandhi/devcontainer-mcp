package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	testPublic   = "https://example.test"
	testResource = testPublic + "/mcp"
	testRedirect = "https://client.test/callback"
	testPassword = "correct horse battery"
)

type fixture struct {
	t      *testing.T
	srv    *Server
	mux    *http.ServeMux
	auth   AuthFile
	secret string
	now    time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	auth, _, secret := issuedSecret(t)
	store, err := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, auth: auth, secret: secret, now: time.Now()}
	srv, err := New(Config{
		PublicURL: testPublic,
		Auth:      auth,
		Store:     store,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:       func() time.Time { return f.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	f.srv = srv
	f.mux = http.NewServeMux()
	srv.Register(f.mux)
	f.mux.Handle("/mcp", srv.RequireToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	return f
}

// issuedSecret builds a fixture whose client secret is known to the test.
func issuedSecret(t *testing.T) (AuthFile, string, string) {
	t.Helper()
	auth, err := NewAuthFile(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	auth, clientID, secret, err := auth.WithClient([]string{testRedirect})
	if err != nil {
		t.Fatal(err)
	}
	return auth, clientID, secret
}

func (f *fixture) do(method, target string, form url.Values, headers map[string]string) *httptest.ResponseRecorder {
	f.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, target, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec
}

type pkce struct{ verifier, challenge string }

func newPKCE(t *testing.T) pkce {
	t.Helper()
	verifier, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(verifier))
	return pkce{verifier: verifier, challenge: base64.RawURLEncoding.EncodeToString(sum[:])}
}

func (f *fixture) authParams(p pkce, resource string) url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {f.auth.ClientID},
		"redirect_uri":          {testRedirect},
		"code_challenge":        {p.challenge},
		"code_challenge_method": {"S256"},
		"resource":              {resource},
		"state":                 {"xyz"},
	}
}

var ticketRe = regexp.MustCompile(`name="ticket" value="([^"]+)"`)

func (f *fixture) loginTicket(p pkce, resource string) string {
	f.t.Helper()
	rec := f.do(http.MethodGet, "/authorize?"+f.authParams(p, resource).Encode(), nil, nil)
	if rec.Code != http.StatusOK {
		f.t.Fatalf("authorize form: %d %s", rec.Code, rec.Body.String())
	}
	m := ticketRe.FindStringSubmatch(rec.Body.String())
	if m == nil {
		f.t.Fatal("login form has no ticket")
	}
	return m[1]
}

func (f *fixture) login(ticket, password, totp string) *httptest.ResponseRecorder {
	return f.do(http.MethodPost, "/authorize", url.Values{"ticket": {ticket}, "password": {password}, "totp": {totp}}, nil)
}

func (f *fixture) currentTOTP() string {
	return totpCode(f.auth.TOTPSecret, f.now.Unix()/30)
}

func codeFrom(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d %s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Query().Get("state") != "xyz" {
		t.Fatalf("state not echoed: %s", loc)
	}
	return loc.Query().Get("code")
}

func basicAuth(id, secret string) map[string]string {
	raw := url.QueryEscape(id) + ":" + url.QueryEscape(secret)
	return map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(raw))}
}

func (f *fixture) exchange(code string, p pkce, resource string) *httptest.ResponseRecorder {
	return f.do(http.MethodPost, "/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {testRedirect},
		"code_verifier": {p.verifier},
		"resource":      {resource},
	}, basicAuth(f.auth.ClientID, f.secret))
}

func tokensFrom(t *testing.T, rec *httptest.ResponseRecorder) (string, string) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("token: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.Access, out.Refresh
}

func bearer(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

func TestFullAuthorizationCodeFlowGrantsMCPAccess(t *testing.T) {
	f := newFixture(t)
	p := newPKCE(t)
	code := codeFrom(t, f.login(f.loginTicket(p, testResource), testPassword, f.currentTOTP()))
	access, _ := tokensFrom(t, f.exchange(code, p, testResource))
	if rec := f.do(http.MethodGet, "/mcp", nil, bearer(access)); rec.Code != http.StatusOK {
		t.Fatalf("MCP with valid token: %d", rec.Code)
	}
}

func TestTokenEndpointRejectsWrongClientSecret(t *testing.T) {
	f := newFixture(t)
	p := newPKCE(t)
	code := codeFrom(t, f.login(f.loginTicket(p, testResource), testPassword, f.currentTOTP()))
	rec := f.do(http.MethodPost, "/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirect},
		"code_verifier": {p.verifier}, "resource": {testResource},
	}, basicAuth(f.auth.ClientID, "wrong-secret"))
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "invalid_client") {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
}

func TestTokenEndpointAcceptsSecretInFormBody(t *testing.T) {
	f := newFixture(t)
	p := newPKCE(t)
	code := codeFrom(t, f.login(f.loginTicket(p, testResource), testPassword, f.currentTOTP()))
	rec := f.do(http.MethodPost, "/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirect},
		"code_verifier": {p.verifier}, "resource": {testResource},
		"client_id": {f.auth.ClientID}, "client_secret": {f.secret},
	}, nil)
	tokensFrom(t, rec)
}

func TestTokenEndpointRequiresClientAuth(t *testing.T) {
	f := newFixture(t)
	rec := f.do(http.MethodPost, "/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x"}}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestMCPWithoutTokenGetsResourceMetadataChallenge(t *testing.T) {
	f := newFixture(t)
	rec := f.do(http.MethodGet, "/mcp", nil, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rec.Code)
	}
	want := `Bearer resource_metadata="` + testPublic + `/.well-known/oauth-protected-resource"`
	if got := rec.Header().Get("WWW-Authenticate"); got != want {
		t.Fatalf("WWW-Authenticate = %q", got)
	}
}

func TestUnknownTokenGetsInvalidTokenChallenge(t *testing.T) {
	f := newFixture(t)
	rec := f.do(http.MethodGet, "/mcp", nil, bearer("made-up"))
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Fatalf("status %d header %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
}

func (f *fixture) registerDynamic(body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec
}

func (f *fixture) dynamicClient(t *testing.T) string {
	t.Helper()
	rec := f.registerDynamic(`{"client_name":"dyn","redirect_uris":["` + testRedirect + `"],"token_endpoint_auth_method":"none"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		ClientID string `json:"client_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	return out.ClientID
}

func TestDynamicClientCompletesFlowWithPKCEAndNoSecret(t *testing.T) {
	f := newFixture(t)
	clientID := f.dynamicClient(t)
	p := newPKCE(t)
	params := f.authParams(p, testResource)
	params.Set("client_id", clientID)
	rec := f.do(http.MethodGet, "/authorize?"+params.Encode(), nil, nil)
	m := ticketRe.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("authorize: %d %s", rec.Code, rec.Body.String())
	}
	code := codeFrom(t, f.login(m[1], testPassword, f.currentTOTP()))
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirect},
		"code_verifier": {p.verifier}, "resource": {testResource}, "client_id": {clientID}}
	access, _ := tokensFrom(t, f.do(http.MethodPost, "/token", form, nil))
	if rec := f.do(http.MethodGet, "/mcp", nil, bearer(access)); rec.Code != http.StatusOK {
		t.Fatalf("MCP with dynamic client token: %d", rec.Code)
	}
}

func TestDynamicClientCannotUseAnotherClientsCode(t *testing.T) {
	f := newFixture(t)
	dyn := f.dynamicClient(t)
	p := newPKCE(t)
	code := codeFrom(t, f.login(f.loginTicket(p, testResource), testPassword, f.currentTOTP()))
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirect},
		"code_verifier": {p.verifier}, "resource": {testResource}, "client_id": {dyn}}
	if rec := f.do(http.MethodPost, "/token", form, nil); rec.Code == http.StatusOK {
		t.Fatal("code issued to the pre-registered client was accepted for another client")
	}
}

func TestUnknownClientIsRejectedAtToken(t *testing.T) {
	f := newFixture(t)
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x"}, "client_id": {"nobody"}}
	if rec := f.do(http.MethodPost, "/token", form, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestRegisterRejectsUnsafeRedirects(t *testing.T) {
	f := newFixture(t)
	for name, body := range map[string]string{
		"plain http non-loopback": `{"redirect_uris":["http://evil.test/cb"]}`,
		"fragment":                `{"redirect_uris":["https://client.test/cb#x"]}`,
		"no redirects":            `{"redirect_uris":[]}`,
		"unsupported auth method": `{"redirect_uris":["https://client.test/cb"],"token_endpoint_auth_method":"private_key_jwt"}`,
	} {
		if rec := f.registerDynamic(body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d", name, rec.Code)
		}
	}
}

func TestRegisterLoopbackRedirectAllowed(t *testing.T) {
	f := newFixture(t)
	if rec := f.registerDynamic(`{"redirect_uris":["http://localhost:33418/callback"]}`); rec.Code != http.StatusCreated {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
}

func TestRegisterCapsClients(t *testing.T) {
	f := newFixture(t)
	for i := 0; i < maxDynamicClients; i++ {
		if rec := f.registerDynamic(`{"redirect_uris":["https://client.test/cb"]}`); rec.Code != http.StatusCreated {
			t.Fatalf("client %d: %d", i, rec.Code)
		}
	}
	if rec := f.registerDynamic(`{"redirect_uris":["https://client.test/cb"]}`); rec.Code != http.StatusForbidden {
		t.Fatalf("client over cap: %d", rec.Code)
	}
}

func TestMetadataDocuments(t *testing.T) {
	f := newFixture(t)
	var pr, as map[string]any
	json.Unmarshal(f.do(http.MethodGet, "/.well-known/oauth-protected-resource", nil, nil).Body.Bytes(), &pr)
	json.Unmarshal(f.do(http.MethodGet, "/.well-known/oauth-authorization-server", nil, nil).Body.Bytes(), &as)
	if pr["resource"] != testResource {
		t.Fatalf("resource = %v", pr["resource"])
	}
	if servers := pr["authorization_servers"].([]any); servers[0] != testPublic {
		t.Fatalf("authorization_servers = %v", servers)
	}
	if as["issuer"] != testPublic || as["token_endpoint"] != testPublic+"/token" {
		t.Fatalf("AS metadata = %v", as)
	}
	if as["registration_endpoint"] != testPublic+"/register" {
		t.Fatalf("registration_endpoint = %v", as["registration_endpoint"])
	}
	methods := as["code_challenge_methods_supported"].([]any)
	if len(methods) != 1 || methods[0] != "S256" {
		t.Fatalf("PKCE methods = %v", methods)
	}
}

func TestWrongPKCEVerifierIsRejected(t *testing.T) {
	f := newFixture(t)
	p := newPKCE(t)
	code := codeFrom(t, f.login(f.loginTicket(p, testResource), testPassword, f.currentTOTP()))
	if rec := f.exchange(code, newPKCE(t), testResource); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_grant") {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
}

func TestAuthorizationCodeIsSingleUse(t *testing.T) {
	f := newFixture(t)
	p := newPKCE(t)
	code := codeFrom(t, f.login(f.loginTicket(p, testResource), testPassword, f.currentTOTP()))
	tokensFrom(t, f.exchange(code, p, testResource))
	if rec := f.exchange(code, p, testResource); rec.Code != http.StatusBadRequest {
		t.Fatalf("second use of code: %d", rec.Code)
	}
}

func TestRedirectURINotRegisteredIsRefusedAtAuthorize(t *testing.T) {
	f := newFixture(t)
	params := f.authParams(newPKCE(t), testResource)
	params.Set("redirect_uri", "https://evil.test/cb")
	if rec := f.do(http.MethodGet, "/authorize?"+params.Encode(), nil, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestWrongClientIDIsRefusedAtAuthorize(t *testing.T) {
	f := newFixture(t)
	params := f.authParams(newPKCE(t), testResource)
	params.Set("client_id", "someone-else")
	if rec := f.do(http.MethodGet, "/authorize?"+params.Encode(), nil, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestResourceMismatchIsRefused(t *testing.T) {
	f := newFixture(t)
	params := f.authParams(newPKCE(t), "https://other.test/mcp")
	if rec := f.do(http.MethodGet, "/authorize?"+params.Encode(), nil, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestPKCEIsRequired(t *testing.T) {
	f := newFixture(t)
	params := f.authParams(newPKCE(t), testResource)
	params.Del("code_challenge")
	if rec := f.do(http.MethodGet, "/authorize?"+params.Encode(), nil, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestTokenBoundToOtherResourceIsRejected(t *testing.T) {
	f := newFixture(t)
	access2, _, err := f.srv.cfg.Store.IssueTokens(f.auth.ClientID, "https://other.test/mcp", f.now, accessTTL, refreshTTL)
	if err != nil {
		t.Fatal(err)
	}
	if rec := f.do(http.MethodGet, "/mcp", nil, bearer(access2)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("token for another resource accepted: %d", rec.Code)
	}
}

func TestWrongPasswordAndLockout(t *testing.T) {
	f := newFixture(t)
	p := newPKCE(t)
	ticket := f.loginTicket(p, testResource)
	for i := 0; i < maxFailures; i++ {
		if rec := f.login(ticket, "wrong password here", f.currentTOTP()); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, rec.Code)
		}
	}
	if rec := f.login(ticket, testPassword, f.currentTOTP()); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("correct login during lockout: %d", rec.Code)
	}
	f.now = f.now.Add(lockoutDuration + time.Second)
	if code := codeFrom(t, f.login(f.loginTicket(p, testResource), testPassword, f.currentTOTP())); code == "" {
		t.Fatal("no code after lockout expired")
	}
}

func TestWrongTOTPIsRejected(t *testing.T) {
	f := newFixture(t)
	p := newPKCE(t)
	code := f.currentTOTP()
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	if rec := f.login(f.loginTicket(p, testResource), testPassword, wrong); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestTOTPCodeCannotBeReplayed(t *testing.T) {
	f := newFixture(t)
	p := newPKCE(t)
	code := f.currentTOTP()
	codeFrom(t, f.login(f.loginTicket(p, testResource), testPassword, code))
	if rec := f.login(f.loginTicket(p, testResource), testPassword, code); rec.Code != http.StatusUnauthorized {
		t.Fatalf("replayed TOTP accepted: %d", rec.Code)
	}
}

func TestRefreshTokenRotatesAndRejectsReuse(t *testing.T) {
	f := newFixture(t)
	p := newPKCE(t)
	code := codeFrom(t, f.login(f.loginTicket(p, testResource), testPassword, f.currentTOTP()))
	_, refresh := tokensFrom(t, f.exchange(code, p, testResource))

	refreshForm := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}
	access2, refresh2 := tokensFrom(t, f.do(http.MethodPost, "/token", refreshForm, basicAuth(f.auth.ClientID, f.secret)))
	if refresh2 == refresh {
		t.Fatal("refresh token not rotated")
	}
	if rec := f.do(http.MethodGet, "/mcp", nil, bearer(access2)); rec.Code != http.StatusOK {
		t.Fatalf("refreshed token rejected: %d", rec.Code)
	}
	if rec := f.do(http.MethodPost, "/token", refreshForm, basicAuth(f.auth.ClientID, f.secret)); rec.Code != http.StatusBadRequest {
		t.Fatalf("reused refresh token accepted: %d", rec.Code)
	}
}

func TestAccessTokenExpires(t *testing.T) {
	f := newFixture(t)
	p := newPKCE(t)
	code := codeFrom(t, f.login(f.loginTicket(p, testResource), testPassword, f.currentTOTP()))
	access, _ := tokensFrom(t, f.exchange(code, p, testResource))
	f.now = f.now.Add(accessTTL + time.Second)
	if rec := f.do(http.MethodGet, "/mcp", nil, bearer(access)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired token accepted: %d", rec.Code)
	}
}

func TestLoginTicketCannotBeTampered(t *testing.T) {
	f := newFixture(t)
	ticket := f.loginTicket(newPKCE(t), testResource)
	parts := strings.SplitN(ticket, ".", 2)
	tampered := strings.Replace(parts[0], "c", "d", 1) + "." + parts[1]
	if rec := f.login(tampered, testPassword, f.currentTOTP()); rec.Code != http.StatusBadRequest {
		t.Fatalf("tampered ticket: %d", rec.Code)
	}
}

func TestLoginTicketExpires(t *testing.T) {
	f := newFixture(t)
	ticket := f.loginTicket(newPKCE(t), testResource)
	f.now = f.now.Add(ticketTTL + time.Second)
	if rec := f.login(ticket, testPassword, f.currentTOTP()); rec.Code != http.StatusBadRequest {
		t.Fatalf("expired ticket: %d", rec.Code)
	}
}

func TestNewRejectsPlainHTTPPublicURL(t *testing.T) {
	auth, _, _ := issuedSecret(t)
	store, _ := OpenStore(filepath.Join(t.TempDir(), "s.json"))
	if _, err := New(Config{PublicURL: "http://203.0.113.10", Auth: auth, Store: store, Logger: slog.Default()}); err == nil {
		t.Fatal("expected refusal for plain http on a public host")
	}
}

func TestTokenRequestWithoutResourceIsAccepted(t *testing.T) {
	f := newFixture(t)
	p := newPKCE(t)
	code := codeFrom(t, f.login(f.loginTicket(p, testResource), testPassword, f.currentTOTP()))
	access, _ := tokensFrom(t, f.exchange(code, p, ""))
	if rec := f.do(http.MethodGet, "/mcp", nil, bearer(access)); rec.Code != http.StatusOK {
		t.Fatalf("token from resource-less exchange rejected: %d", rec.Code)
	}
}

func TestRegisterConfidentialClientGetsSecretAndCanExchange(t *testing.T) {
	f := newFixture(t)
	rec := f.registerDynamic(`{"redirect_uris":["` + testRedirect + `"],"token_endpoint_auth_method":"client_secret_post"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", rec.Code, rec.Body.String())
	}
	var reg struct {
		ClientID string `json:"client_id"`
		Secret   string `json:"client_secret"`
	}
	json.Unmarshal(rec.Body.Bytes(), &reg)
	if reg.Secret == "" {
		t.Fatal("no client_secret issued")
	}
	p := newPKCE(t)
	params := f.authParams(p, testResource)
	params.Set("client_id", reg.ClientID)
	code := codeFrom(t, f.login(f.loginTicketFor(params), testPassword, f.currentTOTP()))
	base := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirect},
		"code_verifier": {p.verifier}, "resource": {testResource}, "client_id": {reg.ClientID}}
	if rec := f.do(http.MethodPost, "/token", base, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("confidential client exchanged without secret: %d", rec.Code)
	}
	base.Set("client_secret", reg.Secret)
	tokensFrom(t, f.do(http.MethodPost, "/token", base, nil))
}

func TestRegisterAcceptsSixRedirectURIs(t *testing.T) {
	f := newFixture(t)
	uris := []string{}
	for _, host := range []string{"oauth-redirect", "oauth-redirect-sandbox", "oauth-redirect-test"} {
		uris = append(uris, `"https://`+host+`.googleusercontent.com/r/x"`, `"https://`+host+`.googleusercontent.com/a/x"`)
	}
	if rec := f.registerDynamic(`{"redirect_uris":[` + strings.Join(uris, ",") + `]}`); rec.Code != http.StatusCreated {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
}

func (f *fixture) loginTicketFor(params url.Values) string {
	f.t.Helper()
	rec := f.do(http.MethodGet, "/authorize?"+params.Encode(), nil, nil)
	m := ticketRe.FindStringSubmatch(rec.Body.String())
	if m == nil {
		f.t.Fatalf("authorize: %d %s", rec.Code, rec.Body.String())
	}
	return m[1]
}
