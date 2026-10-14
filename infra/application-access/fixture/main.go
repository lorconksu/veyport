// Application compatibility fixture. Only synthetic lab credentials belong here.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/websocket"
)

const maxBody = 128 << 20

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type session struct {
	Username string
	Expires  time.Time
}
type fixture struct {
	credentials credentials
	mu          sync.Mutex
	sessions    map[string]session
	requests    map[string]int64
	activeSSE   atomic.Int64
	activeWS    atomic.Int64
	uploaded    atomic.Int64
}

func token() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("fixture entropy unavailable")
	}
	return hex.EncodeToString(b[:])
}
func equal(a, b string) bool {
	ah, bh := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ah[:], bh[:]) == 1
}
func newFixture(c credentials) *fixture {
	return &fixture{credentials: c, sessions: map[string]session{}, requests: map[string]int64{}}
}
func (f *fixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests[r.URL.Path]++
	f.mu.Unlock()
	w.Header().Set("Cache-Control", "no-store")
	switch r.URL.Path {
	case "/health":
		respond(w, map[string]any{"status": "ok"})
	case "/login":
		f.login(w, r)
	case "/logout":
		f.logout(w, r)
	case "/basic":
		user, password, ok := r.BasicAuth()
		if !ok || !equal(user, f.credentials.Username) || !equal(password, f.credentials.Password) {
			w.Header().Set("WWW-Authenticate", `Basic realm="application-fixture"`)
			http.Error(w, "Native Basic login required", http.StatusUnauthorized)
			return
		}
		respond(w, map[string]any{"username": user, "authentication": "basic"})
	case "/whoami":
		user, ok := f.user(r)
		if !ok {
			http.Error(w, "Native cookie login required", http.StatusUnauthorized)
			return
		}
		respond(w, map[string]any{"username": user, "authentication": "cookie"})
	case "/form":
		if r.Method == http.MethodGet {
			csrf := token()
			cookie(w, "fixture_csrf", csrf)
			_ = form.Execute(w, map[string]string{"Token": csrf, "Title": "Native CSRF form", "Action": "form"})
			return
		}
		if r.Method != http.MethodPost || !csrfValid(w, r) {
			http.Error(w, "Native CSRF rejected", http.StatusForbidden)
			return
		}
		respond(w, map[string]any{"csrf": "accepted"})
	case "/inspect":
		// Return names only. Even deliberately sent portal tokens must never be echoed.
		headers := make([]string, 0, len(r.Header))
		for name := range r.Header {
			headers = append(headers, name)
		}
		sort.Strings(headers)
		cookies := []string{}
		for _, c := range r.Cookies() {
			cookies = append(cookies, c.Name)
		}
		sort.Strings(cookies)
		respond(w, map[string]any{"headers": headers, "cookies": cookies, "host": r.Host, "path": r.URL.Path, "raw_query_length": len(r.URL.RawQuery)})
	case "/stats":
		f.mu.Lock()
		counters := map[string]int64{}
		for name, count := range f.requests {
			counters[name] = count
		}
		f.mu.Unlock()
		respond(w, map[string]any{"requests": counters, "active_sse": f.activeSSE.Load(), "active_websocket": f.activeWS.Load(), "uploaded_bytes": f.uploaded.Load()})
	case "/upload":
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			http.Error(w, "POST or PUT required", 405)
			return
		}
		sum := sha256.New()
		count, err := io.CopyBuffer(sum, http.MaxBytesReader(w, r.Body, maxBody), make([]byte, 32<<10))
		if err != nil {
			http.Error(w, "Upload interrupted or too large", 413)
			return
		}
		f.uploaded.Add(count)
		respond(w, map[string]any{"bytes": count, "sha256": hex.EncodeToString(sum.Sum(nil)), "content_length": r.ContentLength})
	case "/download":
		count, err := strconv.ParseInt(r.URL.Query().Get("bytes"), 10, 64)
		if err != nil || count < 1 || count > maxBody {
			http.Error(w, "Invalid byte count", 400)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		block := []byte(strings.Repeat("veyport-fixture-stream\n", 1561))
		for count > 0 {
			n := int64(len(block))
			if count < n {
				n = count
			}
			if _, err := w.Write(block[:n]); err != nil {
				return
			}
			count -= n
			if flush, ok := w.(http.Flusher); ok {
				flush.Flush()
			}
		}
	case "/sse":
		f.sse(w, r)
	case "/ws":
		f.ws(w, r)
	case "/redirect":
		w.Header().Set("Location", "whoami")
		w.WriteHeader(http.StatusFound)
	case "/":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, `<!doctype html><title>Application fixture</title><h1>Private application fixture</h1><p><a href="login">Native login</a> · <a href="basic">HTTP Basic</a> · <a href="form">CSRF form</a></p><p id="identity"></p><button id="events">Start SSE</button><button id="socket">WebSocket echo</button><pre id="output"></pre><script>fetch('whoami').then(r=>r.json()).then(v=>identity.textContent=v.username).catch(()=>{});events.onclick=()=>{let e=new EventSource('sse');e.onmessage=v=>output.textContent+=v.data+'\n';};socket.onclick=()=>{let w=new WebSocket(location.href.replace(/^http/,'ws')+'ws','veyport-fixture');w.onopen=()=>w.send('fixture echo');w.onmessage=v=>{output.textContent+=v.data+'\n';w.close();};};</script>`)
	default:
		http.NotFound(w, r)
	}
}
func respond(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
func cookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

var form = template.Must(template.New("native").Parse(`<!doctype html><title>{{.Title}}</title><h1>{{.Title}}</h1><form action="{{.Action}}" method="post"><input type="hidden" name="csrf" value="{{.Token}}"><label>Username <input name="username" autocomplete="username"></label><label>Password <input name="password" type="password" autocomplete="current-password"></label><button type="submit">Submit native form</button></form>`))

func csrfValid(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if r.ParseForm() != nil {
		return false
	}
	c, err := r.Cookie("fixture_csrf")
	return err == nil && len(c.Value) == 64 && equal(c.Value, r.PostForm.Get("csrf"))
}
func (f *fixture) login(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		csrf := token()
		cookie(w, "fixture_csrf", csrf)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = form.Execute(w, map[string]string{"Token": csrf, "Title": "Native application login", "Action": "login"})
		return
	}
	if r.Method != http.MethodPost || !csrfValid(w, r) {
		http.Error(w, "Native CSRF rejected", 403)
		return
	}
	if !equal(r.PostForm.Get("username"), f.credentials.Username) || !equal(r.PostForm.Get("password"), f.credentials.Password) {
		http.Error(w, "Native credentials rejected", 401)
		return
	}
	value := token()
	f.mu.Lock()
	now := time.Now()
	for key, s := range f.sessions {
		if now.After(s.Expires) {
			delete(f.sessions, key)
		}
	}
	if len(f.sessions) >= 256 {
		f.mu.Unlock()
		http.Error(w, "Fixture session limit", 503)
		return
	}
	f.sessions[value] = session{f.credentials.Username, now.Add(12 * time.Hour)}
	f.mu.Unlock()
	cookie(w, "fixture_session", value)
	w.Header().Set("Location", "whoami")
	w.WriteHeader(303)
}
func (f *fixture) user(r *http.Request) (string, bool) {
	c, err := r.Cookie("fixture_session")
	if err != nil {
		return "", false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sessions[c.Value]
	if !ok || time.Now().After(s.Expires) {
		delete(f.sessions, c.Value)
		return "", false
	}
	return s.Username, true
}
func (f *fixture) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !csrfValid(w, r) {
		http.Error(w, "Native CSRF rejected", 403)
		return
	}
	if c, err := r.Cookie("fixture_session"); err == nil {
		f.mu.Lock()
		delete(f.sessions, c.Value)
		f.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "fixture_session", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true})
	respond(w, map[string]any{"logout": "ok"})
}
func (f *fixture) sse(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unavailable", 500)
		return
	}
	f.activeSSE.Add(1)
	defer f.activeSSE.Add(-1)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for seq := 0; ; seq++ {
		if _, err := fmt.Fprintf(w, "id: %d\ndata: fixture-event-%d\n\n", seq, seq); err != nil {
			return
		}
		flusher.Flush()
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
		}
	}
}

type echoMessage struct {
	data []byte
	kind byte
}

var echoCodec = websocket.Codec{
	Marshal: func(value any) ([]byte, byte, error) {
		message := value.(echoMessage)
		return message.data, message.kind, nil
	},
	Unmarshal: func(data []byte, kind byte, value any) error {
		message := value.(*echoMessage)
		message.data = data
		message.kind = kind
		return nil
	},
}

func (f *fixture) ws(w http.ResponseWriter, r *http.Request) {
	server := websocket.Server{Handshake: func(config *websocket.Config, _ *http.Request) error {
		for _, protocol := range config.Protocol {
			if protocol == "veyport-fixture" {
				config.Protocol = []string{protocol}
				return nil
			}
		}
		config.Protocol = nil
		return nil
	}, Handler: func(conn *websocket.Conn) {
		f.activeWS.Add(1)
		defer f.activeWS.Add(-1)
		defer conn.Close()
		conn.MaxPayloadBytes = 1 << 20
		for {
			var message echoMessage
			_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
			if echoCodec.Receive(conn, &message) != nil {
				return
			}
			if echoCodec.Send(conn, message) != nil {
				return
			}
		}
	}}
	server.ServeHTTP(w, r)
}
func main() {
	path := os.Getenv("FIXTURE_CREDENTIALS_FILE")
	if path == "" {
		log.Fatal("Private fixture credentials file required")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		log.Fatal("Private regular 0600 credentials file required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		log.Fatal("Private fixture credentials unavailable")
	}
	var creds credentials
	if json.Unmarshal(raw, &creds) != nil || creds.Username == "" || len(creds.Password) < 24 {
		log.Fatal("Synthetic fixture credentials rejected")
	}
	addr := os.Getenv("FIXTURE_LISTEN")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	server := &http.Server{Addr: addr, Handler: newFixture(creds), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10, BaseContext: nil}
	cert, key := os.Getenv("FIXTURE_TLS_CERT"), os.Getenv("FIXTURE_TLS_KEY")
	log.Print("Private fixture starting; request content logging disabled")
	if cert != "" && key != "" {
		err = server.ListenAndServeTLS(cert, key)
	} else {
		err = server.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		log.Fatal("Private fixture listener failed")
	}
}
