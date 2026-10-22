package session

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Elagoht/collage/pkg/collage"
)

// UserKey is the key a signed-in reader is stored under, the one RequireUser
// checks: an action that signs a reader in sets it,
//
//	s.Set(session.UserKey, user.ID)
//
// and one that signs them out deletes it.
const UserKey = "user"

// RequireUser returns a guard that lets a signed-in reader through and sends
// everyone else to loginPath, with where they were going in "next":
//
//	private := collage.NewFragment("private", "layouts/private.html").
//		WithGuard(session.RequireUser("/login")).
//		Build()
//
// A reader is signed in when the session holds a value under UserKey. It is
// Require(UserKey, loginPath).
func RequireUser(loginPath string) collage.GuardFunc {
	return Require(UserKey, loginPath)
}

// Require returns a guard that lets through a reader whose session holds a
// value under key, and answers everyone else with 303 See Other to loginPath
// plus "next" — the path and query they asked for, so the login action can send
// them back. A loginPath with a query of its own keeps it.
//
// Next is taken from the request, so it is always a path on this site; the login
// action should still check it before redirecting to it.
//
// The guard needs the session plugin in the application: without it there is no
// session to read, and the guard fails the request with ErrNoSession rather than
// sending every reader to a login that could never let them in.
func Require(key, loginPath string) collage.GuardFunc {
	return require(key, func(context.Context) (string, error) { return loginPath, nil })
}

// RequireUserPage is RequireUser with the login page named rather than its path
// written: the reader is sent to the page registered as loginPage, in the
// locale the request is in — /tr/giris from a Turkish page — so a renamed or
// translated path cannot leave the guard pointing at the old one:
//
//	WithGuard(session.RequireUserPage("login"))
//
// It is RequirePage(UserKey, loginPage).
func RequireUserPage(loginPage string) collage.GuardFunc {
	return RequirePage(UserKey, loginPage)
}

// RequirePage is Require with the login page named rather than its path
// written, its path built with collage.URL for each request. A name the
// application has not registered fails the request, as an unknown name in
// {{pageURL}} fails the render, rather than letting the reader through.
func RequirePage(key, loginPage string) collage.GuardFunc {
	return require(key, func(ctx context.Context) (string, error) {
		return collage.URL(ctx, loginPage, nil)
	})
}

// require is the guard Require and RequirePage return: it lets through a reader
// whose session holds key, and sends anyone else to login plus "next".
func require(key string, login func(context.Context) (string, error)) collage.GuardFunc {
	return func(ctx context.Context, r *http.Request) (*collage.GuardDecision, error) {
		s := FromContext(ctx)
		if s == nil {
			return nil, fmt.Errorf("session: guard for %q: %w", key, ErrNoSession)
		}
		if s.Get(key) != "" {
			return nil, nil
		}
		location, err := login(ctx)
		if err != nil {
			return nil, fmt.Errorf("session: guard for %q: %w", key, err)
		}
		separator := "?"
		if strings.Contains(location, "?") {
			separator = "&"
		}
		return &collage.GuardDecision{
			Status:   http.StatusSeeOther,
			Location: location + separator + "next=" + url.QueryEscape(r.URL.RequestURI()),
		}, nil
	}
}
