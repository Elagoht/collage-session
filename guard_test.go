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
