package session_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	session "github.com/Elagoht/collage-session"
	"github.com/Elagoht/collage/pkg/collage"
	"github.com/Elagoht/collage/pkg/collagetest"
)

// guardSite is an app with a login action that signs the reader in, and a private
// page — wrapped in a layout guarded by guard — with a form of its own.
func guardSite(t *testing.T, guard collage.GuardFunc, withPlugin bool) http.Handler {
	t.Helper()
	private := collage.NewFragment("private", "private.html").WithGuard(guard).Build()
	page := collage.NewPage("panel").
		WithLayouts(private).
		WithContent(collage.NewFragment("panel", "panel.html").Build()).
		WithPath("en", "/panel").
		WithActionFor(collage.NewAction("save").WithMethods(http.MethodPost).WithoutCSRF().
			WithHandler(func(context.Context, *collage.RenderContext) (*collage.ActionResult, error) {
				return &collage.ActionResult{Status: http.StatusNoContent}, nil
			}).Build()).
		Build()
	login := collage.NewAction("login").WithPath("en", "/login").WithMethods(http.MethodPost).WithoutCSRF().
		WithHandler(func(_ context.Context, rc *collage.RenderContext) (*collage.ActionResult, error) {
			s := session.Get(rc)
			s.Regenerate()
			if err := s.Set(session.UserKey, "ada"); err != nil {
				return nil, err
			}
			return &collage.ActionResult{Status: http.StatusNoContent}, nil
		}).Build()
	var plugins []collage.Plugin
	if withPlugin {
		plugins = []collage.Plugin{session.New(session.Options{Key: keyA})}
	}
	return collagetest.NewSite(t,
		collagetest.WithPlugins(plugins...),
		collagetest.WithTemplates(map[string]string{"private.html": `<div>{{slot "content"}}</div>`, "panel.html": `panel`}),
		collagetest.WithoutHome(),
		collagetest.WithRegister(page, login),
	).App.Handler()
}

func signIn(t *testing.T, h http.Handler) []*http.Cookie {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/login", nil))
	if w.Code != http.StatusNoContent {
		t.Fatalf("login = %d", w.Code)
	}
	return w.Result().Cookies()
}

func request(h http.Handler, method, target string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestRequireUser_RedirectsTheSignedOut(t *testing.T) {
	h := guardSite(t, session.RequireUser("/login"), true)
	w := request(h, http.MethodGet, "/panel?tab=2", nil)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/login?next=%2Fpanel%3Ftab%3D2" {
		t.Fatalf("Location = %q", got)
	}
}

func TestRequireUser_LetsTheSignedInThrough(t *testing.T) {
	h := guardSite(t, session.RequireUser("/login"), true)
	cookies := signIn(t, h)
	if w := request(h, http.MethodGet, "/panel", cookies); w.Code != http.StatusOK || w.Body.String() != "<div>panel</div>" {
		t.Fatalf("status = %d body = %q", w.Code, w.Body.String())
	}
}

// A form on a private page is as private as the page.
func TestRequireUser_CoversThePagesForm(t *testing.T) {
	h := guardSite(t, session.RequireUser("/login"), true)
	if w := request(h, http.MethodPost, "/panel", nil); w.Code != http.StatusSeeOther {
		t.Fatalf("signed-out POST = %d, want 303", w.Code)
	}
	if w := request(h, http.MethodPost, "/panel", signIn(t, h)); w.Code != http.StatusNoContent {
		t.Fatalf("signed-in POST = %d, want 204", w.Code)
	}
}

func TestRequireUser_LoginPathWithAQuery(t *testing.T) {
	h := guardSite(t, session.RequireUser("/login?lang=tr"), true)
	w := request(h, http.MethodGet, "/panel", nil)
	if got := w.Header().Get("Location"); got != "/login?lang=tr&next=%2Fpanel" {
		t.Fatalf("Location = %q", got)
	}
}

// Without the plugin there is no session to consult: sending everyone to the
// login page would hide a configuration mistake behind a login loop.
func TestRequireUser_WithoutThePluginFails(t *testing.T) {
	h := guardSite(t, session.RequireUser("/login"), false)
	if w := request(h, http.MethodGet, "/panel", nil); w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	_, err := session.RequireUser("/login")(context.Background(), httptest.NewRequest(http.MethodGet, "/panel", nil))
	if !errors.Is(err, session.ErrNoSession) || !strings.HasPrefix(err.Error(), "session: ") {
		t.Fatalf("guard error = %v, want ErrNoSession under the session: prefix", err)
	}
}

func TestRequire_AnyKey(t *testing.T) {
	h := guardSite(t, session.Require("admin", "/login"), true)
	// Signed in as a user, but not an admin.
	if w := request(h, http.MethodGet, "/panel", signIn(t, h)); w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", w.Code)
	}
}

// pageGuardSite has a login page in English and Turkish, and a private panel in
// both, guarded by guard.
func pageGuardSite(t *testing.T, guard collage.GuardFunc) http.Handler {
	t.Helper()
	private := collage.NewFragment("private", "private.html").WithGuard(guard).Build()
	panel := collage.NewPage("panel").
		WithLayouts(private).
		WithContent(collage.NewFragment("panel", "panel.html").Build()).
		WithPath("en", "/panel").WithPath("tr", "/panel").
		Build()
	login := collage.NewPage("login").
		WithContent(collage.NewFragment("login", "panel.html").Build()).
		WithPath("en", "/login").WithPath("tr", "/giris").
		Build()
	return collagetest.NewSite(t,
		collagetest.WithPlugins(session.New(session.Options{Key: keyA})),
		collagetest.WithConfig(func(c *collage.Config) {
			c.Locale = collage.LocaleConfig{Default: "en", Supported: []string{"en", "tr"}}
		}),
		collagetest.WithTemplates(map[string]string{"private.html": `<div>{{slot "content"}}</div>`, "panel.html": `panel`}),
		collagetest.WithoutHome(),
		collagetest.WithRegister(panel, login),
	).App.Handler()
}

// The login page is named, and its path is the one in the request's locale.
func TestRequireUserPage_RedirectsToTheNamedPage(t *testing.T) {
	h := pageGuardSite(t, session.RequireUserPage("login"))
	for path, want := range map[string]string{
		"/panel?tab=2": "/login?next=%2Fpanel%3Ftab%3D2",
		"/tr/panel":    "/tr/giris?next=%2Ftr%2Fpanel",
	} {
		w := request(h, http.MethodGet, path, nil)
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != want {
			t.Errorf("GET %s = %d to %q, want 303 to %q", path, w.Code, w.Header().Get("Location"), want)
		}
	}
}

// A name nothing is registered under fails the request: nobody is let through,
// and nobody is sent to a page that does not exist.
func TestRequirePage_UnknownNameFailsTheRequest(t *testing.T) {
	h := pageGuardSite(t, session.RequirePage(session.UserKey, "nope"))
	if w := request(h, http.MethodGet, "/panel", nil); w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

// guestSite has a login page in English and Turkish guarded by guard, an
// account page, and an action that signs the reader in. Without the plugin
// there is no session.
func guestSite(t *testing.T, guard collage.GuardFunc, withPlugin bool) http.Handler {
	t.Helper()
	auth := collage.NewFragment("auth", "private.html").WithGuard(guard).Build()
	login := collage.NewPage("login").
		WithLayouts(auth).
		WithContent(collage.NewFragment("login", "panel.html").Build()).
		WithPath("en", "/login").WithPath("tr", "/giris").
		Build()
	account := collage.NewPage("account").
		WithContent(collage.NewFragment("account", "panel.html").Build()).
		WithPath("en", "/account").WithPath("tr", "/hesap").
		Build()
	signin := collage.NewAction("signin").WithPath("en", "/signin").WithMethods(http.MethodPost).WithoutCSRF().
		WithHandler(func(_ context.Context, rc *collage.RenderContext) (*collage.ActionResult, error) {
			if err := session.Get(rc).Set(session.UserKey, "ada"); err != nil {
				return nil, err
			}
			return &collage.ActionResult{Status: http.StatusNoContent}, nil
		}).Build()
	var plugins []collage.Plugin
	if withPlugin {
		plugins = []collage.Plugin{session.New(session.Options{Key: keyA})}
	}
	return collagetest.NewSite(t,
		collagetest.WithPlugins(plugins...),
		collagetest.WithConfig(func(c *collage.Config) {
			c.Locale = collage.LocaleConfig{Default: "en", Supported: []string{"en", "tr"}}
		}),
		collagetest.WithTemplates(map[string]string{"private.html": `<div>{{slot "content"}}</div>`, "panel.html": `panel`}),
		collagetest.WithoutHome(),
		collagetest.WithRegister(login, account, signin),
	).App.Handler()
}

func guestSignIn(t *testing.T, h http.Handler) []*http.Cookie {
	t.Helper()
	w := request(h, http.MethodPost, "/signin", nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("sign in = %d", w.Code)
	}
	return w.Result().Cookies()
}

// A signed-out reader reaches the login page; a signed-in one is sent to a next
// on this site, or home.
func TestRequireGuest(t *testing.T) {
	h := guestSite(t, session.RequireGuest("/account"), true)
	if w := request(h, http.MethodGet, "/login?next=%2Fpanel", nil); w.Code != http.StatusOK {
		t.Fatalf("signed out: status = %d, want 200", w.Code)
	}
	cookies := guestSignIn(t, h)
	for target, want := range map[string]string{
		"/login":                                    "/account",
		"/login?next=%2Fpanel%3Ftab%3D2":            "/panel?tab=2",
		"/login?next=%2F%2Fevil.example":            "/account",
		"/login?next=https%3A%2F%2Fevil.example%2F": "/account",
		"/login?next=%2F%5Cevil.example":            "/account",
	} {
		w := request(h, http.MethodGet, target, cookies)
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != want {
			t.Errorf("signed in, GET %s = %d to %q, want 303 to %q", target, w.Code, w.Header().Get("Location"), want)
		}
	}
}

// The page a signed-in reader is sent to is named, and its path is the one in
// the request's locale.
func TestRequireGuestPage(t *testing.T) {
	h := guestSite(t, session.RequireGuestPage("account"), true)
	cookies := guestSignIn(t, h)
	for target, want := range map[string]string{"/login": "/account", "/tr/giris": "/tr/hesap"} {
		w := request(h, http.MethodGet, target, cookies)
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != want {
			t.Errorf("GET %s = %d to %q, want 303 to %q", target, w.Code, w.Header().Get("Location"), want)
		}
	}
	if w := request(h, http.MethodGet, "/tr/giris", nil); w.Code != http.StatusOK {
		t.Errorf("signed out: status = %d, want 200", w.Code)
	}
}

// Without the plugin, or with a page name nothing is registered under, the
// request fails rather than guessing.
func TestRequireGuest_Failures(t *testing.T) {
	if w := request(guestSite(t, session.RequireGuest("/account"), false), http.MethodGet, "/login", nil); w.Code != http.StatusInternalServerError {
		t.Errorf("without the plugin: status = %d, want 500", w.Code)
	}
	h := guestSite(t, session.RequireGuestPage("nope"), true)
	if w := request(h, http.MethodGet, "/login", guestSignIn(t, h)); w.Code != http.StatusInternalServerError {
		t.Errorf("unknown page, signed in: status = %d, want 500", w.Code)
	}
}
