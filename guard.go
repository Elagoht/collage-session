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
	separator := "?"
	if strings.Contains(loginPath, "?") {
		separator = "&"
	}
	return func(ctx context.Context, r *http.Request) (*collage.GuardDecision, error) {
		s := FromContext(ctx)
		if s == nil {
			return nil, fmt.Errorf("session guard for %q: %w", key, ErrNoSession)
		}
		if s.Get(key) != "" {
			return nil, nil
		}
		return &collage.GuardDecision{
			Status:   http.StatusSeeOther,
			Location: loginPath + separator + "next=" + url.QueryEscape(r.URL.RequestURI()),
		}, nil
	}
}
