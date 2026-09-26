package session_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	session "github.com/Elagoht/collage-session"
	"github.com/Elagoht/collage/pkg/collage"
)

var (
	keyA = bytes.Repeat([]byte("a"), 32)
	keyB = bytes.Repeat([]byte("b"), 32)
)

type site struct {
	h       http.Handler
	renders atomic.Int64
}

type answer struct {
	ID    string `json:"id"`
	User  string `json:"user"`
	Error string `json:"error"`
	Too   bool   `json:"tooLarge"`
}

func newSite(t *testing.T, opts session.Options, pluginConfig string) *site {
	t.Helper()
	s := &site{}
	cfg := &collage.Config{
		Server: collage.ServerConfig{Host: "localhost", Port: 3000},
		Template: collage.TemplateConfig{FS: fstest.MapFS{
			"t/p.html": {Data: []byte(`<main>{{with .}}signed in as {{.}}{{else}}anonymous{{end}}</main>`)},
		}, Root: "t"},
		Cache:   collage.CacheConfig{Enabled: true, Type: "memory", DefaultTTL: time.Hour},
		Plugins: []collage.Plugin{session.New(opts)},
	}
	if pluginConfig != "" {
		cfg.PluginConfig = map[string]json.RawMessage{session.Name: []byte(pluginConfig)}
	}
	app, err := collage.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	content := collage.NewFragment("p", "p.html").WithDataHandler(
		func(_ context.Context, rc *collage.RenderContext) (any, []string, error) { // any: collage's data handler signature
			s.renders.Add(1)
			return session.Get(rc).Get("user"), nil, nil
		}).Build()
	// Static, so it is cached: a signed-in reader's page must never be the cached one.
	if err := app.RegisterPage(collage.NewPage("account").WithContent(content).WithPath("en", "/account").Static().Build()); err != nil {
		t.Fatal(err)
	}
	action := func(name string, fn func(s *session.Session, r *http.Request) answer) {
		t.Helper()
		if err := app.RegisterAction(collage.NewAction(name).WithPath("en", "/"+name).WithMethods(http.MethodGet).WithHandler(
			func(_ context.Context, rc *collage.RenderContext) (*collage.ActionResult, error) {
				s := session.Get(rc)
				a := fn(s, rc.Request)
				a.ID, a.User = s.ID(), s.Get("user")
				return collage.JSONOf(http.StatusOK, a)
			}).Build()); err != nil {
			t.Fatal(err)
		}
	}
	errAnswer := func(err error) answer {
		if err == nil {
			return answer{}
		}
		return answer{Error: err.Error(), Too: errors.Is(err, session.ErrTooLarge)}
	}
	action("login", func(s *session.Session, r *http.Request) answer {
		s.Regenerate()
		return errAnswer(s.Set("user", r.URL.Query().Get("user")))
	})
	action("logout", func(s *session.Session, _ *http.Request) answer { s.Clear(); return answer{} })
	action("forget", func(s *session.Session, _ *http.Request) answer { s.Delete("user"); return answer{} })
	action("whoami", func(*session.Session, *http.Request) answer { return answer{} })
	action("big", func(s *session.Session, _ *http.Request) answer {
		return errAnswer(s.Set("blob", strings.Repeat("x", 5000)))
	})
	action("busy", func(s *session.Session, _ *http.Request) answer {
		// A page's data handlers run at the same time; so may these.
		var wg sync.WaitGroup
		for i := range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = s.Set("k"+string(rune('a'+i)), "v")
				_ = s.Get("user")
			}()
		}
		wg.Wait()
		return answer{}
	})
	s.h = app.Handler()
	return s
}

func (s *site) get(path string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	for _, c := range cookies {
		if c != nil {
			r.AddCookie(c)
		}
	}
	rec := httptest.NewRecorder()
	s.h.ServeHTTP(rec, r)
	return rec
}

func (s *site) ask(t *testing.T, path string, cookies ...*http.Cookie) (answer, *http.Cookie) {
	t.Helper()
	rec := s.get(path, cookies...)
	var a answer
	if err := json.Unmarshal(rec.Body.Bytes(), &a); err != nil {
		t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
	}
	return a, sessionCookie(rec)
}

func sessionCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	return cookieNamed(rec, "collage_session")
}

func cookieNamed(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// Signed in by an action, recognised on the next request, never in the cached page
// someone else is served — and anonymous readers still get the cached one.
func TestSessionAndTheCache(t *testing.T) {
	s := newSite(t, session.Options{Key: keyA}, "")
	if body := s.get("/account").Body.String(); !strings.Contains(body, "anonymous") {
		t.Fatalf("anonymous page: %s", body)
	}
	a, c := s.ask(t, "/login?user=ada")
	if a.Error != "" || c == nil || c.Value == "" {
		t.Fatalf("login: %+v, cookie %+v", a, c)
	}
	if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Secure {
		t.Errorf("cookie attributes: %+v", c)
	}
	if c.MaxAge < 604790 || c.MaxAge > 604800 {
		t.Errorf("Max-Age %d, want a week", c.MaxAge)
	}

	before := s.renders.Load()
	mine := s.get("/account", c)
	if !strings.Contains(mine.Body.String(), "signed in as ada") {
		t.Errorf("the reader's page: %s", mine.Body.String())
	}
	if cc := mine.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("a signed-in page is cacheable: %q", cc)
	}
	if s.renders.Load() != before+1 {
		t.Error("a signed-in page was not rendered fresh")
	}
	if sessionCookie(mine) != nil {
		t.Error("an unchanged session was written back")
	}

	before = s.renders.Load()
	other := s.get("/account")
	if strings.Contains(other.Body.String(), "ada") {
		t.Errorf("another reader saw the session's page: %s", other.Body.String())
	}
	if s.renders.Load() != before {
		t.Error("an anonymous reader was not served from the cache")
	}
}

// A new id after signing in, the same id while nothing changes.
func TestRegenerate(t *testing.T) {
	s := newSite(t, session.Options{Key: keyA}, "")
	first, c := s.ask(t, "/login?user=ada")
	same, _ := s.ask(t, "/whoami", c)
	again, _ := s.ask(t, "/login?user=ada", c)
	if first.ID == "" || same.ID != first.ID || again.ID == first.ID {
		t.Errorf("ids: %q, %q, %q", first.ID, same.ID, again.ID)
	}
}

// Clearing, or emptying, the session removes the cookie.
func TestClearAndDelete(t *testing.T) {
	s := newSite(t, session.Options{Key: keyA}, "")
	for _, path := range []string{"/logout", "/forget"} {
		_, c := s.ask(t, "/login?user=ada")
		a, gone := s.ask(t, path, c)
		if a.User != "" || gone == nil || gone.MaxAge >= 0 {
			t.Errorf("%s: %+v, cookie %+v", path, a, gone)
		}
	}
	// Clearing a session that never existed sends nothing.
	if _, c := s.ask(t, "/logout"); c != nil {
		t.Errorf("a cookie for nothing: %+v", c)
	}
}

// A cookie the site did not write is not a session, does not skip the cache, and
// is cleared.
func TestForgedCookie(t *testing.T) {
	s := newSite(t, session.Options{Key: keyA}, "")
	_, c := s.ask(t, "/login?user=ada")
	payload := strings.Split(c.Value, ".")
	body, _ := base64.RawURLEncoding.DecodeString(payload[1])
	payload[1] = base64.RawURLEncoding.EncodeToString(bytes.Replace(body, []byte("ada"), []byte("eve"), 1))
	forged := &http.Cookie{Name: c.Name, Value: strings.Join(payload, ".")}

	s.get("/account") // cached
	before := s.renders.Load()
	rec := s.get("/account", forged)
	if !strings.Contains(rec.Body.String(), "anonymous") || s.renders.Load() != before {
		t.Errorf("a forged cookie was honoured, or skipped the cache: %s", rec.Body.String())
	}
	if gone := sessionCookie(rec); gone == nil || gone.MaxAge >= 0 {
		t.Errorf("a forged cookie was not cleared: %+v", gone)
	}
	// Signed for another cookie name is forged too.
	other := newSite(t, session.Options{Key: keyA, Cookie: "other"}, "")
	if a, _ := other.ask(t, "/whoami", &http.Cookie{Name: "other", Value: c.Value}); a.User != "" {
		t.Error("a value signed for one cookie was accepted as another")
	}
}

// Encrypted, the reader cannot read what the session holds.
func TestEncrypt(t *testing.T) {
	s := newSite(t, session.Options{Key: keyA, Encrypt: true}, "")
	_, c := s.ask(t, "/login?user=ada-lovelace")
	if !strings.HasPrefix(c.Value, "e.") {
		t.Fatalf("not encrypted: %s", c.Value)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(strings.Split(c.Value, ".")[1])
	if bytes.Contains(raw, []byte("ada-lovelace")) {
		t.Error("the session can be read from the cookie")
	}
	if a, _ := s.ask(t, "/whoami", c); a.User != "ada-lovelace" {
		t.Errorf("round trip: %+v", a)
	}
	// A signed cookie from before encryption was turned on is kept, and rewritten
	// encrypted.
	plain := newSite(t, session.Options{Key: keyA}, "")
	_, pc := plain.ask(t, "/login?user=ada")
	a, rewritten := s.ask(t, "/whoami", pc)
	if a.User != "ada" || rewritten == nil || !strings.HasPrefix(rewritten.Value, "e.") {
		t.Errorf("upgrade: %+v, %+v", a, rewritten)
	}
}

// A new key with the old one among PreviousKeys signs nobody out; without it, the
// old cookies are refused.
func TestKeyRotation(t *testing.T) {
	old := newSite(t, session.Options{Key: keyA, Encrypt: true}, "")
	_, c := old.ask(t, "/login?user=ada")

	rotated := newSite(t, session.Options{Key: keyB, PreviousKeys: [][]byte{keyA}, Encrypt: true}, "")
	a, rewritten := rotated.ask(t, "/whoami", c)
	if a.User != "ada" || rewritten == nil {
		t.Fatalf("rotation: %+v, rewritten %+v", a, rewritten)
	}
	fresh := newSite(t, session.Options{Key: keyB, Encrypt: true}, "")
	if a, _ := fresh.ask(t, "/whoami", rewritten); a.User != "ada" {
		t.Error("the rewritten cookie is not under the new key")
	}
	if a, _ := fresh.ask(t, "/whoami", c); a.User != "" {
		t.Error("a cookie under a dropped key was accepted")
	}
}

// A value that would take the cookie past what a browser keeps is refused, and the
// session is left as it was.
func TestTooLarge(t *testing.T) {
	s := newSite(t, session.Options{Key: keyA}, "")
	_, c := s.ask(t, "/login?user=ada")
	a, written := s.ask(t, "/big", c)
	if !a.Too || !strings.Contains(a.Error, "4096") || a.User != "ada" || written != nil {
		t.Errorf("big: %+v, cookie %+v", a, written)
	}
}

// A session ends MaxAge after it started, and IdleTimeout after its last request.
func TestExpiry(t *testing.T) {
	lifetime := newSite(t, session.Options{Key: keyA, MaxAge: 1}, "")
	idle := newSite(t, session.Options{Key: keyA, IdleTimeout: 1}, "")
	_, lc := lifetime.ask(t, "/login?user=ada")
	_, ic := idle.ask(t, "/login?user=ada")
	if lc.MaxAge != 1 || ic.MaxAge != 1 {
		t.Errorf("Max-Age %d and %d, want 1", lc.MaxAge, ic.MaxAge)
	}
	// Under an idle limit, an active reader's cookie is rewritten to push it back.
	if _, touched := idle.ask(t, "/whoami", ic); touched == nil {
		t.Error("an active session under an idle limit was not refreshed")
	}
	time.Sleep(1100 * time.Millisecond)
	for name, s := range map[string]struct {
		site *site
		c    *http.Cookie
	}{"maxAge": {lifetime, lc}, "idleTimeout": {idle, ic}} {
		a, gone := s.site.ask(t, "/whoami", s.c)
		if a.User != "" || gone == nil || gone.MaxAge >= 0 {
			t.Errorf("%s: expired session honoured: %+v, cookie %+v", name, a, gone)
		}
	}
}

// Secure over TLS or behind a proxy that says so, or always when asked.
func TestSecure(t *testing.T) {
	s := newSite(t, session.Options{Key: keyA}, "")
	r := httptest.NewRequest(http.MethodGet, "/login?user=ada", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	s.h.ServeHTTP(rec, r)
	if c := sessionCookie(rec); c == nil || !c.Secure {
		t.Errorf("not Secure behind an HTTPS proxy: %+v", c)
	}
	strict := newSite(t, session.Options{Key: keyA, Secure: true, SameSite: "strict", Path: "/app", Domain: "example.com"}, "")
	if _, c := strict.ask(t, "/login?user=ada"); c == nil || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/app" || c.Domain != "example.com" {
		t.Errorf("options not applied: %+v", c)
	}
}

// Configuration carries the key hex-encoded, and overlays the Go options.
func TestConfiguration(t *testing.T) {
	old := newSite(t, session.Options{Key: keyA, Cookie: "sid"}, "")
	c := cookieNamed(old.get("/login?user=ada"), "sid")
	if c == nil {
		t.Fatal("no cookie under the configured name")
	}
	cfg := `{"key": "` + hex.EncodeToString(keyB) + `", "previousKeys": ["` + hex.EncodeToString(keyA) + `"], "cookie": "sid", "maxAge": 60}`
	s := newSite(t, session.Options{Key: keyA}, cfg)
	rec := s.get("/whoami", c)
	var a answer
	_ = json.Unmarshal(rec.Body.Bytes(), &a)
	rewritten := cookieNamed(rec, "sid")
	if a.User != "ada" || rewritten == nil || rewritten.MaxAge > 60 {
		t.Errorf("configuration not applied: %+v, %+v", a, rewritten)
	}
}

// Anything wrong with the configuration stops the application from starting.
func TestMisconfiguration(t *testing.T) {
	for name, opts := range map[string]session.Options{
		"short key":          {Key: []byte("short")},
		"bad hex":            {KeyHex: "zz"},
		"short previous key": {Key: keyA, PreviousKeys: [][]byte{[]byte("short")}},
		"bad previous hex":   {Key: keyA, PreviousKeysHex: []string{"zz"}},
		"sameSite none":      {Key: keyA, SameSite: "none"},
		"sameSite typo":      {Key: keyA, SameSite: "lux"},
		"negative maxAge":    {Key: keyA, MaxAge: -1},
		"negative idle":      {Key: keyA, IdleTimeout: -5},
		"bad cookie name":    {Key: keyA, Cookie: "a b"},
	} {
		rec := newSite(t, opts, "").get("/account")
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: started, %d", name, rec.Code)
		}
	}
	// Without a key, one is generated and the application runs.
	if rec := newSite(t, session.Options{}, "").get("/account"); rec.Code != http.StatusOK {
		t.Errorf("no key: %d", rec.Code)
	}
}

func TestConcurrentUse(t *testing.T) {
	s := newSite(t, session.Options{Key: keyA}, "")
	if _, c := s.ask(t, "/busy"); c == nil {
		t.Error("no cookie after concurrent sets")
	}
}

// Outside a request the plugin wraps, a session reads as empty and refuses to be
// set.
func TestOutsideARequest(t *testing.T) {
	s := session.FromContext(context.Background())
	if s != nil || session.Get(nil) != nil {
		t.Fatal("a session outside a request")
	}
	s.Delete("x")
	s.Clear()
	s.Regenerate()
	if s.Get("x") != "" || s.ID() != "" || !errors.Is(s.Set("x", "y"), session.ErrNoSession) {
		t.Error("a nil session is not empty")
	}
}
