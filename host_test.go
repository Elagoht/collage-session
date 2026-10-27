package session_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	session "github.com/Elagoht/collage-session"
	"github.com/Elagoht/collage/pkg/collage"
	"github.com/Elagoht/collage/pkg/collagetest"
)

// tenants stands in for collage-tenant: a plugin resolving each host to its own
// origin, which makes the application multi-origin.
type tenants struct{}

func (tenants) Name() string                             { return "test/tenants" }
func (tenants) Version() string                          { return "0.0.0" }
func (tenants) Init(context.Context, collage.Host) error { return nil }
func (tenants) Shutdown(context.Context) error           { return nil }
func (tenants) Origin(_ context.Context, host string) (string, bool) {
	return "https://" + host, true
}

func (s *site) askAt(t *testing.T, url string, cookies ...*http.Cookie) (answer, *http.Cookie) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, url, nil)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	s.h.ServeHTTP(rec, r)
	var a answer
	if err := json.Unmarshal(rec.Body.Bytes(), &a); err != nil {
		t.Fatalf("%s: %d %s", url, rec.Code, rec.Body.String())
	}
	return a, sessionCookie(rec)
}

// A session cookie issued on one host is no session on another: a reader of
// tenant acme replaying their cookie on globex is anonymous there (audit
// PLUGA-02). The host is compared without its port and in any case.
func TestCookieIsBoundToItsHost(t *testing.T) {
	for name, extra := range map[string][]collagetest.SiteOption{
		"one origin":   nil,
		"multi-origin": {collagetest.WithPlugins(tenants{})},
	} {
		for _, encrypt := range []bool{false, true} {
			s := newSite(t, session.Options{Key: keyA, Encrypt: encrypt}, "", extra...)
			_, c := s.askAt(t, "http://acme.test/login?user=7")
			if c == nil || c.Value == "" {
				t.Fatalf("%s: no cookie", name)
			}
			if a, _ := s.askAt(t, "http://ACME.test:8080/whoami", c); a.User != "7" {
				t.Errorf("%s encrypt=%v: refused on its own host: %+v", name, encrypt, a)
			}
			a, cleared := s.askAt(t, "http://globex.test/whoami", c)
			if a.User != "" || a.ID != "" {
				t.Errorf("%s encrypt=%v: acme's cookie is a session on globex: %+v", name, encrypt, a)
			}
			// Ignored, not cleared: under a Domain shared by both hosts, clearing
			// it would sign the reader out of acme.
			if cleared != nil {
				t.Errorf("%s encrypt=%v: another host's cookie was cleared: %+v", name, encrypt, cleared)
			}
		}
	}
}

// The audit's case end to end: RequireUser on globex refuses acme's cookie.
func TestRequireUserRefusesAnotherHostsCookie(t *testing.T) {
	account := collage.NewPage("acct").
		WithContent(collage.NewFragment("acct", "p.html").WithGuard(session.RequireUser("/signin")).Build()).
		WithPath("en", "/acct").
		Build()
	s := newSite(t, session.Options{Key: keyA}, "", collagetest.WithPlugins(tenants{}), collagetest.WithRegister(account))
	_, c := s.askAt(t, "http://acme.test/login?user=7")
	for host, want := range map[string]int{"acme.test": http.StatusOK, "globex.test": http.StatusSeeOther} {
		r := httptest.NewRequest(http.MethodGet, "http://"+host+"/acct", nil)
		r.AddCookie(c)
		rec := httptest.NewRecorder()
		s.h.ServeHTTP(rec, r)
		if rec.Code != want {
			t.Errorf("%s: %d, want %d", host, rec.Code, want)
		}
	}
}

// legacyCookie is a cookie as v0.6.0 and earlier signed it: no host inside.
func legacyCookie(key []byte, user string) *http.Cookie {
	now := time.Now().Unix()
	body, _ := json.Marshal(struct {
		ID      string            `json:"i"`
		Data    map[string]string `json:"d"`
		Created int64             `json:"c"`
		Seen    int64             `json:"s"`
	}{"legacy-id", map[string]string{"user": user}, now, now})
	payload := "s." + base64.RawURLEncoding.EncodeToString(body)
	derived := hmac.New(sha256.New, key)
	derived.Write([]byte("collage-session sign"))
	mac := hmac.New(sha256.New, derived.Sum(nil))
	mac.Write([]byte("collage_session\x00" + payload))
	return &http.Cookie{Name: "collage_session", Value: payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))}
}

// A cookie from before v0.7.0 carries no host. On a one-origin application
// there is no other host to replay it on, so it is accepted and rewritten bound
// to the host it arrived on: nobody is signed out by the upgrade. On a
// multi-origin application it is refused and cleared, since it cannot say which
// tenant issued it.
func TestCookieWithoutAHost(t *testing.T) {
	old := legacyCookie(keyA, "ada")

	one := newSite(t, session.Options{Key: keyA}, "")
	a, bound := one.askAt(t, "http://acme.test/whoami", old)
	if a.User != "ada" || bound == nil || bound.Value == "" {
		t.Fatalf("one origin: a v0.6.0 cookie was not kept and rewritten: %+v, %+v", a, bound)
	}
	if a, _ := one.askAt(t, "http://acme.test/whoami", bound); a.User != "ada" {
		t.Errorf("one origin: the rewritten cookie: %+v", a)
	}
	if a, _ := one.askAt(t, "http://globex.test/whoami", bound); a.User != "" {
		t.Errorf("one origin: the rewritten cookie is not bound to its host: %+v", a)
	}

	multi := newSite(t, session.Options{Key: keyA}, "", collagetest.WithPlugins(tenants{}))
	a, cleared := multi.askAt(t, "http://globex.test/whoami", old)
	if a.User != "" {
		t.Errorf("multi-origin: a cookie without a host was honoured: %+v", a)
	}
	if cleared == nil || cleared.MaxAge >= 0 {
		t.Errorf("multi-origin: a cookie without a host was not cleared: %+v", cleared)
	}
}

// With Domain set on a one-origin application, the session is bound to the
// domain: every host under it shares the session, as setting Domain asks. On a
// multi-origin application each host is a tenant, and the session stays bound to
// its host whatever the Domain.
func TestCookieUnderADomain(t *testing.T) {
	one := newSite(t, session.Options{Key: keyA, Domain: ".Example.test"}, "")
	_, c := one.askAt(t, "http://www.example.test/login?user=ada")
	if a, _ := one.askAt(t, "http://example.test/whoami", c); a.User != "ada" {
		t.Errorf("one origin: refused on the domain itself: %+v", a)
	}
	if a, _ := one.askAt(t, "http://shop.example.test/whoami", c); a.User != "ada" {
		t.Errorf("one origin: refused under the domain: %+v", a)
	}
	if a, _ := one.askAt(t, "http://example.other/whoami", c); a.User != "" {
		t.Errorf("one origin: accepted outside the domain: %+v", a)
	}

	multi := newSite(t, session.Options{Key: keyA, Domain: "example.test"}, "", collagetest.WithPlugins(tenants{}))
	_, c = multi.askAt(t, "http://acme.example.test/login?user=7")
	if a, _ := multi.askAt(t, "http://acme.example.test/whoami", c); a.User != "7" {
		t.Errorf("multi-origin: refused on its own host: %+v", a)
	}
	if a, _ := multi.askAt(t, "http://globex.example.test/whoami", c); a.User != "" {
		t.Errorf("multi-origin: accepted on another tenant under the domain: %+v", a)
	}
}
