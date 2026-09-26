# elagoht/session

A collage plugin for a session kept in a cookie: a small map of strings the site
signs with HMAC-SHA256, and can encrypt with AES-GCM, with no database behind it.
collage keeps state out of its core; this is where a site that needs "who is
signed in" gets it.

```go
app, err := collage.New(&collage.Config{
	Plugins: []collage.Plugin{session.New(session.Options{Key: key})},
})
```

Requires collage v0.23.0 or later. It adds no template function, so it can be
registered with `RegisterPlugin` as well as in `Config.Plugins`.

## Using it

An action signs a reader in, and redirects, as an accepted form should:

```go
func login(ctx context.Context, rc *collage.RenderContext) (*collage.ActionResult, error) {
	user, err := accounts.Check(ctx, rc.Request.PostFormValue("email"), rc.Request.PostFormValue("password"))
	if err != nil {
		// ... render the form again, 422 ...
	}
	s := session.Get(rc)
	s.Regenerate()
	if err := s.Set("user", user.ID); err != nil {
		return nil, err
	}
	return collage.SeeOther("/account"), nil
}
```

A data handler reads it, and signing out is `Clear`:

```go
userID := session.Get(rc).Get("user")
```

| Method | |
| --- | --- |
| `Get(key)` | The value, or `""` |
| `Set(key, value) error` | Stores it, starting the session if there was none |
| `Delete(key)` | Removes one key |
| `Clear()` | Removes everything, and the cookie with it |
| `Regenerate()` | A new id and a new lifetime, the data kept — call it when a reader signs in |
| `ID()` | The session's id, `""` before it starts |

`session.Get(rc)` is the render's session; a handler of your own uses
`session.FromContext(r.Context())`. Outside a request the plugin wraps — a static
build — it is `nil`, which reads as empty and whose `Set` returns `ErrNoSession`.
The session is safe to use from a page's data handlers, which run at the same time.

Values are strings, which keeps the cookie small and its encoding obvious: store an
id and look the rest up, rather than the record itself.

## The cache

**A page rendered for a reader with a session may show that reader's data** — their
name in the header, their basket. collage caches rendered pages and serves one
copy to everyone, so a request carrying a valid session cookie is answered with a
fresh render that is neither read from the page cache nor written to it, and
marked `private, no-store` (`collage.SkipCache`, from the plugin's middleware).

A reader without a session — most of a public site's traffic — is served from the
cache exactly as before. So is a reader sending a cookie that does not verify:
only a cookie the site signed turns the cache off, so a forged one cannot be used
to force fresh renders. Such a cookie, like an expired one, is cleared.

Two things follow:

- **Set a session from an action**, or from a page that is not cached. A cached
  page's data handler runs once, for whoever asked first, and a session started
  there is started for that reader alone.
- **A signed-in reader costs a render per page.** That is the price of showing them
  their own page; it is why a public page should not start a session for everyone
  who visits it.

## The cookie

`HttpOnly`, `SameSite=Lax`, `Path=/`, and `Secure` when the request arrived over
TLS or through a proxy that says so with `X-Forwarded-Proto: https` — always, with
`Secure`. The response carries `Set-Cookie` **only when the session changed**: a
reader who is only reading costs no header. The exceptions are a session under an
idle limit, rewritten at most every quarter of `IdleTimeout` to push the limit back,
and one signed with a previous key, rewritten under the current one.

Signed only, the reader can read what the session holds and cannot change it. With
`Encrypt`, they cannot read it either. The cookie's name is bound into the
signature, so a value cannot be moved from one cookie to another.

A browser keeps four kilobytes of a cookie and silently drops one past that — the
reader is signed out for no visible reason. `Set` refuses a value that would take
the cookie past `session.MaxCookieSize` with an error wrapping `session.ErrTooLarge`
that names the key and the size, and changes nothing.

A session ends `MaxAge` seconds after it started or was regenerated, and
`IdleTimeout` seconds after its last request when that is set. Both times are
inside the signature, so a reader cannot extend them.

## Forgery

Cross-site request forgery is collage's job, not this plugin's: every form
collage renders carries a signed token, and every unsafe request to an action is
checked. `SameSite=Lax` is a second line, not the first.

## The key

Set a key of at least 32 random bytes, the same on every instance and across
restarts — `openssl rand -hex 32` makes one. Without one, a key is generated per
process and a warning logged: every reader is signed out by a restart, or by
reaching another instance.

To rotate it, make the new key `key` and put the old one in `previousKeys`. A
cookie under the old key is still accepted and rewritten under the new one, so
nobody is signed out; drop the old key once `maxAge` has passed.

## Configuration

```go
session.New(session.Options{
	Key:         key,
	Encrypt:     true,
	MaxAge:      30 * 24 * 60 * 60,
	IdleTimeout: 2 * 60 * 60,
})
```

```json
{
  "elagoht/session": {
    "key": "hex-encoded, 32 bytes or more",
    "previousKeys": ["the key before it, hex-encoded"],
    "encrypt": true,
    "cookie": "collage_session",
    "path": "/",
    "domain": "",
    "maxAge": 604800,
    "idleTimeout": 0,
    "secure": false,
    "sameSite": "lax"
  }
}
```

| Option | Default | |
| --- | --- | --- |
| `key` | generated per process | Signs, and with `encrypt` encrypts, the cookie |
| `previousKeys` | none | Keys still accepted, and rewritten under `key` |
| `encrypt` | `false` | Encrypt with AES-GCM, so the reader cannot read the session |
| `cookie` | `collage_session` | The cookie's name |
| `path`, `domain` | `/`, none | The cookie's scope |
| `maxAge` | `604800`, a week | Seconds a session lives from its start |
| `idleTimeout` | `0`, none | Seconds without a request that end a session |
| `secure` | `false`: when the request is HTTPS | `Secure` on every cookie |
| `sameSite` | `lax` | `lax`, `strict`, or `none`, which needs `secure` |

A key that is not hex or shorter than 32 bytes, a negative duration, an unknown
`sameSite`, `none` without `secure`, and a cookie name a browser would refuse all
stop the application from starting.

## Limitations

- **A session cannot be revoked.** It lives in the reader's cookie, not on the
  server, so `Clear` removes the reader's copy and nothing else: a copy taken
  earlier stays valid until it expires. Keep `maxAge` short where that matters, or
  keep a server-side record the session's id is checked against.
- A session holds strings, and about 3 KB of them once encoded.
- Two requests from one reader at the same time each read the cookie as it was and
  each write their own; the later response wins, and the earlier one's change is
  lost. A cookie cannot be locked.
- A page served from the cache runs no data handler, so it cannot start, change or
  refresh a session; see [The cache](#the-cache).
