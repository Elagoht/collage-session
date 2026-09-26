// Package session is a collage plugin for a session kept in a cookie: a small map
// of strings the site signs, and can encrypt, with no database behind it.
//
//	app, err := collage.New(&collage.Config{
//		Plugins: []collage.Plugin{session.New(session.Options{Key: key})},
//	})
//
// An action signs a reader in:
//
//	func login(ctx context.Context, rc *collage.RenderContext) (*collage.ActionResult, error) {
//		user, err := accounts.Check(ctx, rc.Request.PostFormValue("email"), rc.Request.PostFormValue("password"))
//		if err != nil {
//			// ... refuse ...
//		}
//		s := session.Get(rc)
//		s.Regenerate() // a new id for a new privilege
//		if err := s.Set("user", user.ID); err != nil {
//			return nil, err
//		}
//		return collage.SeeOther("/account"), nil
//	}
//
// and a data handler reads it with session.Get(rc).Get("user").
//
// A page rendered for a reader with a session may show that reader's data, so a
// request carrying a valid session cookie is answered with a fresh render that is
// neither read from the page cache nor written to it. A reader without one is
// served from the cache as before.
package session

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Elagoht/collage/pkg/collage"
)

// Name is the plugin's name, and the key its configuration is found under.
const Name = "elagoht/session"

// MaxCookieSize is the most a session cookie's name and value may take together:
// what every browser keeps of one cookie. Past it a browser drops the cookie
// without a word, and the reader is signed out for no visible reason.
const MaxCookieSize = 4096

var (
	// ErrTooLarge is returned by Set when the value would make the cookie larger
	// than MaxCookieSize. Nothing is changed.
	ErrTooLarge = errors.New("session: the cookie would be larger than a browser keeps")
	// ErrNoSession is returned by Set outside a request the plugin wraps: a static
	// build, a handler the plugin was not registered for.
	ErrNoSession = errors.New("session: no session in this request; is the plugin registered?")
	// ErrCommitted is returned by Set once the response's headers are sent, when
	// there is no longer a way to send the cookie.
	ErrCommitted = errors.New("session: the response has started; the session can no longer change")
)

// Options configures the plugin.
type Options struct {
	// Key signs the cookie, and encrypts it with Encrypt: at least 32 random
	// bytes, the same on every instance and across restarts. Unset, one is
	// generated per process, and every reader is signed out by a restart or by
	// reaching another instance. In configuration it is "key", hex-encoded.
	Key []byte `json:"-"`
	// KeyHex is Key, hex-encoded, as configuration carries it.
	KeyHex string `json:"key"`
	// PreviousKeys are keys a cookie is still accepted under, and rewritten under
	// Key: rotating the key signs nobody out. Drop one once MaxAge has passed.
	PreviousKeys [][]byte `json:"-"`
	// PreviousKeysHex is PreviousKeys, hex-encoded, as configuration carries them.
	PreviousKeysHex []string `json:"previousKeys"`
	// Encrypt encrypts the session with AES-GCM, so the reader cannot read what it
	// holds. Without it the session is only signed: the reader can read it, and
	// cannot change it.
	Encrypt bool `json:"encrypt"`
	// Cookie is the cookie's name. Default "collage_session".
	Cookie string `json:"cookie"`
	// Path is the cookie's path. Default "/".
	Path string `json:"path"`
	// Domain is the cookie's domain. Default none: the host that set it.
	Domain string `json:"domain"`
	// MaxAge is how many seconds a session lives from when it was started or
	// regenerated, however active its reader. Default 604800, a week.
	MaxAge int `json:"maxAge"`
	// IdleTimeout is how many seconds without a request end a session. Default 0,
	// no idle limit. With one, the cookie is rewritten as the reader keeps coming
	// back, at most every quarter of the timeout.
	IdleTimeout int `json:"idleTimeout"`
	// Secure sends the cookie over HTTPS only, always. Without it the cookie is
	// Secure when the request arrived over TLS, or through a proxy that says so
	// with X-Forwarded-Proto: https.
	Secure bool `json:"secure"`
	// SameSite is "lax" (the default), "strict" or "none". "none" needs Secure.
	SameSite string `json:"sameSite"`
}

// Plugin keeps sessions.
type Plugin struct {
	opts     Options
	log      *slog.Logger
	keys     []keySet // Key first, then PreviousKeys
	sameSite http.SameSite
}

// keySet is one key and the two keys derived from it, so signing and encrypting
// never use the same key for two purposes.
type keySet struct {
	mac []byte
	enc cipher.AEAD
}

var _ collage.Plugin = (*Plugin)(nil)

// New returns a plugin with opts as its starting point, which the application's
// own configuration is then decoded over.
func New(opts Options) *Plugin { return &Plugin{opts: opts} }

func (p *Plugin) Name() string                   { return Name }
func (p *Plugin) Version() string                { return "0.1.1" }
func (p *Plugin) Shutdown(context.Context) error { return nil }

// Init reads the configuration, refuses what is wrong with it, and wraps every
// request to load its session and write it back.
func (p *Plugin) Init(_ context.Context, host collage.Host) error {
	if err := host.Config(&p.opts); err != nil {
		return err
	}
	p.log = host.Logger()
	if err := p.configure(host.DevMode()); err != nil {
		return err
	}
	return host.Use(p.middleware)
}

func (p *Plugin) configure(dev bool) error {
	o := &p.opts
	if o.KeyHex != "" {
		key, err := hex.DecodeString(o.KeyHex)
		if err != nil {
			return fmt.Errorf("session: key: %w", err)
		}
		o.Key = key
	}
	for i, h := range o.PreviousKeysHex {
		key, err := hex.DecodeString(h)
		if err != nil {
			return fmt.Errorf("session: previousKeys[%d]: %w", i, err)
		}
		o.PreviousKeys = append(o.PreviousKeys, key)
	}
	if len(o.Key) == 0 {
		o.Key = make([]byte, 32)
		_, _ = rand.Read(o.Key)
		// A generated key is right for a first run in development and wrong to
		// deploy, which is what collage says of its own forgery key too.
		msg := "session: no key set, so one was generated for this process; every reader is signed out by a restart, or by reaching another instance"
		if dev {
			p.log.Info(msg)
		} else {
			p.log.Warn(msg)
		}
	}
	p.keys = nil
	for i, key := range append([][]byte{o.Key}, o.PreviousKeys...) {
		if len(key) < 32 {
			if i == 0 {
				return errors.New("session: the key must be at least 32 bytes")
			}
			return fmt.Errorf("session: previous key %d must be at least 32 bytes", i-1)
		}
		ks, err := derive(key)
		if err != nil {
			return err
		}
		p.keys = append(p.keys, ks)
	}
	if o.Cookie == "" {
		o.Cookie = "collage_session"
	}
	if err := (&http.Cookie{Name: o.Cookie, Value: "x"}).Valid(); err != nil {
		return fmt.Errorf("session: cookie: %w", err)
	}
	if o.Path == "" {
		o.Path = "/"
	}
	if o.MaxAge == 0 {
		o.MaxAge = 7 * 24 * 60 * 60
	}
	if o.MaxAge < 0 || o.IdleTimeout < 0 {
		return errors.New("session: maxAge and idleTimeout are seconds, and cannot be negative")
	}
	switch strings.ToLower(o.SameSite) {
	case "", "lax":
		p.sameSite = http.SameSiteLaxMode
	case "strict":
		p.sameSite = http.SameSiteStrictMode
	case "none":
		// A browser refuses SameSite=None without Secure, so the setting would
		// be a cookie that is never stored.
		if !o.Secure {
			return errors.New(`session: sameSite "none" needs secure`)
		}
		p.sameSite = http.SameSiteNoneMode
	default:
		return fmt.Errorf("session: sameSite %q: want lax, strict or none", o.SameSite)
	}
	return nil
}

func derive(key []byte) (keySet, error) {
	sub := func(purpose string) []byte {
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte("collage-session " + purpose))
		return mac.Sum(nil)
	}
	block, err := aes.NewCipher(sub("encrypt"))
	if err != nil {
		return keySet{}, fmt.Errorf("session: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return keySet{}, fmt.Errorf("session: %w", err)
	}
	return keySet{mac: sub("sign"), enc: aead}, nil
}

// state is what the cookie carries. Created and Seen are inside the signature, so
// a reader cannot extend a session by editing them.
type state struct {
	ID      string            `json:"i"`
	Data    map[string]string `json:"d,omitempty"`
	Created int64             `json:"c"`
	Seen    int64             `json:"s"`
}

// Session is one reader's session. It is safe for concurrent use: a page's data
// handlers run at the same time.
type Session struct {
	mu     sync.Mutex
	plugin *Plugin
	req    *http.Request
	state  state
	// loaded is whether a valid cookie arrived; arrived whether any cookie of the
	// session's name did, valid or not, so that an expired or forged one is
	// cleared.
	loaded, arrived bool
	// changed is whether the application changed the session; stale whether the
	// cookie must be rewritten anyway — its reader active under an idle limit, or
	// it was signed with a previous key.
	changed, stale bool
	committed      bool
}

type sessionKey struct{}

// Get returns the render's session: FromContext of its request's context.
func Get(rc *collage.RenderContext) *Session {
	if rc == nil {
		return nil
	}
	return FromContext(rc.Context())
}

// FromContext returns the session of the request ctx belongs to, for a handler of
// your own. Outside a request the plugin wraps it is nil, and a nil *Session reads
// as empty and refuses to be set.
func FromContext(ctx context.Context) *Session {
	if ctx == nil {
		return nil
	}
	s, _ := ctx.Value(sessionKey{}).(*Session)
	return s
}

// ID is the session's identifier, which Regenerate replaces. "" for a session that
// has not been started.
func (s *Session) ID() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.ID
}

// Get returns the value stored under key, or "".
func (s *Session) Get(key string) string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.Data[key]
}

// Set stores value under key, starting the session if there was none. It refuses
// with ErrTooLarge a value that would take the cookie past MaxCookieSize, and
// changes nothing then.
func (s *Session) Set(key, value string) error {
	if s == nil {
		return ErrNoSession
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.committed {
		return ErrCommitted
	}
	next := s.state
	next.Data = make(map[string]string, len(s.state.Data)+1)
	for k, v := range s.state.Data {
		next.Data[k] = v
	}
	next.Data[key] = value
	if next.ID == "" {
		now := time.Now().Unix()
		next.ID, next.Created = newID(), now
	}
	// The size is known only once the value is encoded — encrypted, signed — so
	// encode it, and refuse here, where the caller can still do something about it.
	next.Seen = time.Now().Unix()
	if size := len(s.plugin.opts.Cookie) + 1 + len(s.plugin.encode(next)); size > MaxCookieSize {
		return fmt.Errorf("%w: setting %q would make it %d bytes, over %d", ErrTooLarge, key, size, MaxCookieSize)
	}
	s.state = next
	s.changed = true
	return nil
}

// Delete removes key. A session left empty is removed with its cookie.
func (s *Session) Delete(key string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Data[key]; ok && !s.committed {
		data := make(map[string]string, len(s.state.Data))
		for k, v := range s.state.Data {
			if k != key {
				data[k] = v
			}
		}
		s.state.Data = data
		s.changed = true
	}
}

// Clear removes everything, and with it the cookie: signing out.
func (s *Session) Clear() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.committed {
		s.state = state{}
		s.changed = true
	}
}

// Regenerate gives the session a new id and a new lifetime, keeping its data. Call
// it when a reader's privileges change — signing in above all — so an id someone
// learned before is not the id of the signed-in session.
func (s *Session) Regenerate() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.committed {
		s.state.ID, s.state.Created = newID(), time.Now().Unix()
		s.changed = true
	}
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (p *Plugin) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := p.load(r)
		if s.loaded {
			// A page rendered for this reader may show this reader's data, and
			// must not be the page the cache hands the next one. Only a cookie
			// that verifies counts: a forged one cannot force fresh renders.
			_ = collage.SkipCache(r)
		}
		sw := &sessionWriter{ResponseWriter: w, session: s}
		next.ServeHTTP(sw, r.WithContext(context.WithValue(r.Context(), sessionKey{}, s)))
		sw.commit()
	})
}

func (p *Plugin) load(r *http.Request) *Session {
	s := &Session{plugin: p, req: r}
	cookie, err := r.Cookie(p.opts.Cookie)
	if err != nil {
		return s
	}
	s.arrived = true
	st, keyIndex, ok := p.decode(cookie.Value)
	if !ok || st.ID == "" || len(st.Data) == 0 {
		return s
	}
	now := time.Now().Unix()
	if now-st.Created >= int64(p.opts.MaxAge) {
		return s
	}
	if idle := int64(p.opts.IdleTimeout); idle > 0 {
		if now-st.Seen >= idle {
			return s
		}
		if now-st.Seen >= idle/4 {
			s.stale = true
		}
	}
	// A cookie under a previous key, or in the other form than Encrypt asks for,
	// is rewritten in the current one.
	if keyIndex > 0 || strings.HasPrefix(cookie.Value, "e.") != p.opts.Encrypt {
		s.stale = true
	}
	s.state, s.loaded = st, true
	return s
}

// sessionWriter writes the cookie before the headers go out.
type sessionWriter struct {
	http.ResponseWriter
	session *Session
}

func (w *sessionWriter) commit() {
	s := w.session
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.committed {
		return
	}
	s.committed = true
	p := s.plugin
	switch {
	case len(s.state.Data) > 0 && (s.changed || s.stale):
		s.state.Seen = time.Now().Unix()
		value := p.encode(s.state)
		if len(p.opts.Cookie)+1+len(value) > MaxCookieSize {
			// Set refuses what would not fit, so this is only the timestamps'
			// few bytes; keeping the old cookie is better than one a browser drops.
			p.log.Error("session: the cookie outgrew what a browser keeps, and was not written", "size", len(value))
			return
		}
		http.SetCookie(w.ResponseWriter, p.cookie(s.req, value, p.remaining(s.state)))
	case len(s.state.Data) == 0 && s.arrived:
		// Cleared, emptied, expired or forged: the browser should stop sending it.
		http.SetCookie(w.ResponseWriter, p.cookie(s.req, "", -1))
	}
}

func (w *sessionWriter) WriteHeader(status int) {
	w.commit()
	w.ResponseWriter.WriteHeader(status)
}

func (w *sessionWriter) Write(b []byte) (int, error) {
	w.commit()
	return w.ResponseWriter.Write(b)
}

// Flush passes a flush through.
func (w *sessionWriter) Flush() {
	w.commit()
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the connection.
func (w *sessionWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// remaining is how many seconds the browser should keep the cookie: until the
// session's lifetime ends, or its idle limit, whichever is sooner.
func (p *Plugin) remaining(st state) int {
	left := p.opts.MaxAge - int(time.Now().Unix()-st.Created)
	if p.opts.IdleTimeout > 0 && p.opts.IdleTimeout < left {
		left = p.opts.IdleTimeout
	}
	return max(left, 1)
}

func (p *Plugin) cookie(r *http.Request, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     p.opts.Cookie,
		Value:    value,
		Path:     p.opts.Path,
		Domain:   p.opts.Domain,
		MaxAge:   maxAge,
		HttpOnly: true,
		SameSite: p.sameSite,
		Secure:   p.opts.Secure || r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"),
	}
}

// encode is "s." base64url(JSON) or "e." base64url(nonce ‖ AES-GCM), then "."
// base64url(HMAC-SHA256) of what came before, under the current key.
func (p *Plugin) encode(st state) string {
	body, _ := json.Marshal(st)
	ks := p.keys[0]
	var payload string
	if p.opts.Encrypt {
		nonce := make([]byte, ks.enc.NonceSize())
		_, _ = rand.Read(nonce)
		// The cookie's name is the additional data, so a value cannot be moved to
		// another cookie encrypted under the same key.
		sealed := ks.enc.Seal(nonce, nonce, body, []byte(p.opts.Cookie))
		payload = "e." + base64.RawURLEncoding.EncodeToString(sealed)
	} else {
		payload = "s." + base64.RawURLEncoding.EncodeToString(body)
	}
	return payload + "." + base64.RawURLEncoding.EncodeToString(p.sign(ks, payload))
}

// decode verifies value under each key in turn, and says which one it was.
func (p *Plugin) decode(value string) (state, int, bool) {
	i := strings.LastIndexByte(value, '.')
	if i < 0 {
		return state{}, 0, false
	}
	payload := value[:i]
	sig, err := base64.RawURLEncoding.DecodeString(value[i+1:])
	if err != nil {
		return state{}, 0, false
	}
	kind, data, ok := strings.Cut(payload, ".")
	if !ok {
		return state{}, 0, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		return state{}, 0, false
	}
	for index, ks := range p.keys {
		if !hmac.Equal(sig, p.sign(ks, payload)) {
			continue
		}
		body := raw
		switch kind {
		case "s":
		case "e":
			n := ks.enc.NonceSize()
			if len(raw) < n {
				return state{}, 0, false
			}
			body, err = ks.enc.Open(nil, raw[:n], raw[n:], []byte(p.opts.Cookie))
			if err != nil {
				return state{}, 0, false
			}
		default:
			return state{}, 0, false
		}
		var st state
		if json.Unmarshal(body, &st) != nil {
			return state{}, 0, false
		}
		return st, index, true
	}
	return state{}, 0, false
}

// sign binds the cookie's name into the signature, so a value signed for one
// cookie is not accepted as another.
func (p *Plugin) sign(ks keySet, payload string) []byte {
	mac := hmac.New(sha256.New, ks.mac)
	mac.Write([]byte(p.opts.Cookie + "\x00" + payload))
	return mac.Sum(nil)
}
