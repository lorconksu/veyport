package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/model"
)

type applicationConnection struct {
	session, app string
	cancel       context.CancelFunc
}
type applicationConnections struct {
	mu     sync.Mutex
	active map[string]applicationConnection
}

func newApplicationConnections() *applicationConnections {
	return &applicationConnections{active: map[string]applicationConnection{}}
}
func (c *applicationConnections) register(id, session, app string, cancel context.CancelFunc) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.active) >= 128 {
		return false
	}
	n := 0
	for _, v := range c.active {
		if v.session == session {
			n++
		}
	}
	if n >= 8 {
		return false
	}
	c.active[id] = applicationConnection{session, app, cancel}
	return true
}
func (c *applicationConnections) remove(id string) { c.mu.Lock(); delete(c.active, id); c.mu.Unlock() }
func (c *applicationConnections) closeWhere(match func(applicationConnection) bool) {
	c.mu.Lock()
	out := []context.CancelFunc{}
	for _, v := range c.active {
		if match(v) {
			out = append(out, v.cancel)
		}
	}
	c.mu.Unlock()
	for _, cancel := range out {
		cancel()
	}
}
func (c *applicationConnections) closeApp(id string) {
	c.closeWhere(func(v applicationConnection) bool { return v.app == id })
}
func (c *applicationConnections) closeSession(id string) {
	c.closeWhere(func(v applicationConnection) bool { return v.session == id })
}
func (c *applicationConnections) closeAll() {
	c.closeWhere(func(applicationConnection) bool { return true })
}
func (s *Server) applicationHostRouter(portal http.Handler) http.Handler {
	launchLimiter := newRateLimiter(30, time.Minute)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.applicationDomain != "" && (r.Method == http.MethodGet || r.Method == http.MethodHead) && r.URL.EscapedPath() == "/api/health" {
			peer, _, err := net.SplitHostPort(r.RemoteAddr)
			if err == nil {
				if ip := net.ParseIP(peer); ip != nil && ip.IsLoopback() {
					s.handleHealth(w, r)
					return
				}
			}
		}
		if s.applicationDomain == "" {
			portal.ServeHTTP(w, r)
			return
		}
		if r.Host == s.applicationPortalHost() {
			wrapped := &applicationPortalDocumentWriter{ResponseWriter: w, launch: applicationLaunchDocumentPath(r.URL.Path)}
			portal.ServeHTTP(wrapped, r)
			return
		}
		host := strings.ToLower(r.Host)
		if host != r.Host || strings.Contains(host, ":") || !strings.HasSuffix(host, "."+s.applicationDomain) {
			http.Error(w, "unknown host", http.StatusMisdirectedRequest)
			return
		}
		a, e := s.store.GetApplicationByHost(host)
		if e != nil {
			http.Error(w, "application unavailable", http.StatusNotFound)
			return
		}
		w.Header().Set("Referrer-Policy", "strict-origin")
		if r.URL.Path == "/_veyport/launch" {
			launchLimiter.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.exchangeApplicationLaunch(w, r, a) })).ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/_veyport/") {
			http.Error(w, "gateway route unavailable", 404)
			return
		}
		s.serveApplication(w, r, a)
	})
}
func uniqueApplicationCookie(r *http.Request) (string, error) {
	value := ""
	n := 0
	for _, c := range r.Cookies() {
		if c.Name == applicationCookie {
			value = c.Value
			n++
		}
	}
	if n != 1 || len(value) > 100 {
		return "", errApplicationDenied
	}
	return value, nil
}
func (s *Server) applicationUnauthenticated(w http.ResponseWriter, r *http.Request, a *model.Application) {
	w.Header().Set("Cache-Control", "no-store")
	s.applicationAudit(r, "application.denied", a.ID, "authentication_required")
	if (r.Method == "GET" || r.Method == "HEAD") && (r.Header.Get("Sec-Fetch-Dest") == "document" || strings.Contains(r.Header.Get("Accept"), "text/html")) {
		path, e := applicationPath(r.URL.RequestURI())
		if e != nil {
			http.Error(w, "invalid application destination", 400)
			return
		}
		destination, e := applicationPortalRedirect(s.applicationPortalOrigin, a.ID, path)
		if e != nil {
			http.Error(w, "portal login route unavailable", 503)
			return
		}
		// Origin/authority come solely from fixed operator configuration; the
		// validated app path is encoded as a query value, never a redirect authority.
		// nosemgrep: go.lang.security.injection.open-redirect.open-redirect
		http.Redirect(w, r, destination, http.StatusFound)
		return
	}
	http.Error(w, "application authentication required", http.StatusUnauthorized)
}
func (s *Server) exchangeApplicationLaunch(w http.ResponseWriter, r *http.Request, a *model.Application) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost || r.Header.Get("Origin") != s.applicationPortalOrigin {
		http.Error(w, "launch origin refused", 403)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if e := r.ParseForm(); e != nil {
		http.Error(w, "invalid launch", 400)
		return
	}
	ticket := r.PostForm.Get("ticket")
	if len(ticket) != 43 {
		http.Error(w, "invalid launch", 403)
		return
	}
	credential, e := applicationSecret()
	if e != nil {
		http.Error(w, "launch unavailable", 500)
		return
	}
	meta, e := s.store.GetApplicationTicket(refreshDigest(ticket), a.PublicHostname, s.now())
	if e != nil {
		http.Error(w, "launch expired", 403)
		return
	}
	anchor, e := s.store.GetApplicationAnchor(meta.AnchorID)
	if e != nil || anchor.RevokedAt != nil {
		http.Error(w, "login revoked", 403)
		return
	}
	expires := anchor.CompletedMFAAt.Add(time.Duration(s.applicationPolicy().MaxSeconds) * time.Second)
	if !s.now().Before(expires) {
		http.Error(w, "sign in again", 401)
		return
	}
	id := uuid.NewString()
	path, e := s.store.ConsumeApplicationTicket(refreshDigest(ticket), a.PublicHostname, model.ApplicationSession{ID: id, CredentialDigest: refreshDigest(credential), ExpiresAt: expires}, s.now())
	if e != nil {
		http.Error(w, "launch expired", 403)
		return
	}
	path, e = applicationPath(path)
	if e != nil {
		_ = s.store.EndApplicationSession(id, "launch_denied", s.now())
		s.applicationAudit(r, "application.denied", a.ID, "invalid_destination")
		http.Error(w, "invalid application destination", 400)
		return
	}
	ss, e := s.store.GetApplicationSession(refreshDigest(credential))
	if e != nil || s.checkApplicationSession(r.Context(), a, ss, false) != nil {
		_ = s.store.EndApplicationSession(id, "launch_denied", s.now())
		s.applicationAudit(r, "application.denied", a.ID, "launch_denied")
		http.Error(w, "launch access denied", 403)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: applicationCookie, Value: credential, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: expires, MaxAge: int(expires.Sub(s.now()).Seconds())})
	// applicationPath validates this consumed ticket destination at the sink:
	// root-relative only; no authority, scheme, backslash or control characters.
	// nosemgrep: go.lang.security.injection.open-redirect.open-redirect
	http.Redirect(w, r, path, http.StatusSeeOther)
}
func appRequestOriginAllowed(r *http.Request, host string) bool {
	unsafe := isMutationMethod(r.Method) || strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
	if !unsafe {
		return true
	}
	origin := r.Header.Get("Origin")
	if origin != "" {
		return origin == "https://"+host
	}
	return !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") && r.Header.Get("Sec-Fetch-Site") == "same-origin"
}
func reservedApplicationCookie(name string) bool {
	return strings.HasPrefix(name, "__Host-veyport_") || strings.HasPrefix(name, "veyport_") || strings.HasPrefix(name, "aerodocs_")
}
func stripApplicationCredentials(r *http.Request) {
	cookies := r.Cookies()
	r.Header.Del("Cookie")
	for _, c := range cookies {
		if !reservedApplicationCookie(c.Name) {
			r.AddCookie(c)
		}
	}
	for _, h := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Veyport-User", "X-Veyport-Token"} {
		r.Header.Del(h)
	}
}

type applicationWriter struct {
	http.ResponseWriter
	status   int
	bytes    atomic.Int64
	ctx      context.Context
	mu       sync.Mutex
	hijacked net.Conn
	finished bool
	readers  int
}

func (w *applicationWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
func (w *applicationWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *applicationWriter) Write(b []byte) (int, error) {
	if e := w.armDeadline(false); e != nil {
		return 0, e
	}
	n, e := w.ResponseWriter.Write(b)
	w.bytes.Add(int64(n))
	return n, e
}
func (w *applicationWriter) FlushError() error {
	if e := w.armDeadline(false); e != nil {
		return e
	}
	return http.NewResponseController(w.ResponseWriter).Flush()
}
func (w *applicationWriter) Flush() { _ = w.FlushError() }
func (w *applicationWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, e := http.NewResponseController(w.ResponseWriter).Hijack()
	if e != nil {
		return nil, nil, e
	}
	_ = conn.SetReadDeadline(time.Time{})
	_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	w.status = http.StatusSwitchingProtocols
	w.mu.Lock()
	w.hijacked = conn
	w.mu.Unlock()
	if w.ctx.Err() != nil {
		_ = conn.Close()
		return nil, nil, w.ctx.Err()
	}
	return applicationWriteConn{Conn: conn, bytes: &w.bytes}, rw, nil
}

// Serialize deadline resets against cancellation. Holding this lock during
// socket I/O would prevent cancellation from interrupting a blocked operation.
func (w *applicationWriter) armDeadline(read bool) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if e := w.ctx.Err(); e != nil {
		return e
	}
	controller := http.NewResponseController(w.ResponseWriter)
	var e error
	if read {
		e = controller.SetReadDeadline(time.Now().Add(30 * time.Second))
	} else {
		e = controller.SetWriteDeadline(time.Now().Add(30 * time.Second))
	}
	if e != nil && !errors.Is(e, http.ErrNotSupported) {
		return e
	}
	if read {
		w.readers++
	}
	return nil
}
func (w *applicationWriter) finish() { w.mu.Lock(); w.finished = true; w.mu.Unlock() }
func (w *applicationWriter) interruptFrontend() {
	w.mu.Lock()
	controller := http.NewResponseController(w.ResponseWriter)
	// Normal handler completion must still permit net/http to flush final bytes.
	// An upload reader can outlive an early upstream response and still needs
	// interruption even when the response handler has completed.
	if !w.finished || w.readers > 0 {
		_ = controller.SetReadDeadline(time.Now())
	}
	if !w.finished {
		_ = controller.SetWriteDeadline(time.Now())
	}
	conn := w.hijacked
	w.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

type applicationBody struct {
	bytes atomic.Int64
	io.ReadCloser
	writer *applicationWriter
}

func (b *applicationBody) Read(p []byte) (int, error) {
	// ReadController is unsupported by recorders, but real server sockets must
	// still be cancellable. Preserve the context check independently of support.
	e := b.writer.armDeadline(true)
	if e != nil && !errors.Is(e, http.ErrNotSupported) {
		return 0, e
	}
	defer func() { b.writer.mu.Lock(); b.writer.readers--; b.writer.mu.Unlock() }()
	n, e := b.ReadCloser.Read(p)
	b.bytes.Add(int64(n))
	return n, e
}
func (b *applicationBody) Close() error {
	if b.writer.ctx.Err() != nil {
		_ = http.NewResponseController(b.writer.ResponseWriter).SetReadDeadline(time.Now())
	}
	return b.ReadCloser.Close()
}
func (s *Server) serveApplication(w http.ResponseWriter, r *http.Request, a *model.Application) {
	credential, e := uniqueApplicationCookie(r)
	if e != nil {
		s.applicationUnauthenticated(w, r, a)
		return
	}
	ss, e := s.store.GetApplicationSession(refreshDigest(credential))
	if e != nil || s.checkApplicationSession(r.Context(), a, ss, false) != nil {
		s.applicationUnauthenticated(w, r, a)
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), ctxUserID, ss.UserID))
	if !appRequestOriginAllowed(r, a.PublicHostname) || r.Method == http.MethodConnect || r.URL.IsAbs() {
		s.applicationAudit(r, "application.denied", a.ID, "origin_or_target_refused")
		http.Error(w, "application request refused", 403)
		return
	}
	if _, e = applicationPath(r.URL.RequestURI()); e != nil {
		http.Error(w, "invalid application path", 400)
		return
	}
	if s.applicationDialer == nil {
		http.Error(w, "application proxy unavailable", 503)
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), ctxUserID, ss.UserID))
	requestID := uuid.NewString()
	r = r.WithContext(context.WithValue(r.Context(), ctxRequestID, requestID))
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	if !s.applicationStreams.register(requestID, ss.ID, a.ID, cancel) {
		http.Error(w, "application connection capacity reached", 429)
		return
	}
	defer s.applicationStreams.remove(requestID)
	aw := &applicationWriter{ResponseWriter: w, ctx: ctx, status: http.StatusOK}
	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(time.Time{})
	_ = controller.SetWriteDeadline(time.Time{})
	r = r.WithContext(ctx)
	r.Body = &applicationBody{ReadCloser: r.Body, writer: aw}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				aw.interruptFrontend()
				return
			case <-ticker.C:
				current, e := s.store.GetApplication(a.ID)
				fresh, e2 := s.store.ApplicationSessionByID(ss.ID)
				if e != nil || e2 != nil || s.checkApplicationSession(ctx, current, fresh, false) != nil {
					cancel()
					aw.interruptFrontend()
					s.auditApplicationSessionEnds()
					return
				}
			}
		}
	}()
	defer func() { aw.finish(); cancel(); <-finished }()
	target, e := applicationTarget(a)
	if e != nil {
		http.Error(w, "backend configuration invalid", 502)
		return
	}
	backend, e := url.Parse(a.BackendURL)
	if e != nil {
		http.Error(w, "backend configuration invalid", 502)
		return
	}
	roots := (*x509.CertPool)(nil)
	if a.CAPEM != "" {
		roots = x509.NewCertPool()
		if !applicationCertificatePEM(a.CAPEM) || !roots.AppendCertsFromPEM([]byte(a.CAPEM)) {
			http.Error(w, "backend TLS configuration invalid", 502)
			return
		}
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: target.Hostname, RootCAs: roots}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 30 * time.Second, MaxResponseHeaderBytes: 1 << 20, DialContext: func(_ context.Context, network, address string) (net.Conn, error) {
		conn, e := s.applicationDialer.DialApplication(ctx, target)
		if e != nil {
			return nil, e
		}
		go func() { <-ctx.Done(); _ = conn.Close() }()
		return applicationWriteConn{Conn: conn}, nil
	}}
	defer transport.CloseIdleConnections()
	proxy := &httputil.ReverseProxy{Transport: transport, FlushInterval: -1, ErrorLog: log.New(io.Discard, "", 0), Rewrite: func(pr *httputil.ProxyRequest) {
		stripApplicationCredentials(pr.Out)
		pr.SetURL(backend)
		pr.Out.Host = backend.Host
		pr.Out.Header.Set("X-Forwarded-Host", a.PublicHostname)
		pr.Out.Header.Set("X-Forwarded-Proto", "https")
		if pr.In.Header.Get("Origin") == "https://"+a.PublicHostname {
			pr.Out.Header.Set("Origin", backend.Scheme+"://"+backend.Host)
		}
	}, ModifyResponse: func(resp *http.Response) error { return rewriteApplicationResponse(resp, a, backend) }, ErrorHandler: func(w http.ResponseWriter, r *http.Request, e error) {
		if errors.Is(ctx.Err(), context.Canceled) {
			return
		}
		http.Error(w, "application backend unavailable", http.StatusBadGateway)
	}}
	if e = s.store.TouchApplicationSession(ss.ID, s.now()); e != nil {
		http.Error(w, "application authority unavailable", 503)
		return
	}
	started := time.Now()
	proxy.ServeHTTP(aw, r)
	s.auditApplicationRequest(r, a, aw, started)
}
func rewriteApplicationResponse(resp *http.Response, a *model.Application, backend *url.URL) error {
	cookies := resp.Cookies()
	resp.Header.Del("Set-Cookie")
	for _, c := range cookies {
		if reservedApplicationCookie(c.Name) {
			continue
		}
		if c.Domain != "" && !strings.EqualFold(strings.TrimPrefix(c.Domain, "."), backend.Hostname()) {
			continue
		}
		c.Domain = ""
		c.Secure = true
		if backend.Path != "" && backend.Path != "/" && (c.Path == strings.TrimSuffix(backend.Path, "/") || strings.HasPrefix(c.Path, strings.TrimSuffix(backend.Path, "/")+"/")) {
			c.Path = strings.TrimPrefix(c.Path, strings.TrimSuffix(backend.Path, "/"))
			if c.Path == "" {
				c.Path = "/"
			}
		}
		resp.Header.Add("Set-Cookie", c.String())
	}
	if raw := resp.Header.Get("Location"); raw != "" {
		u, e := url.Parse(raw)
		if e != nil {
			return errApplicationDenied
		}
		prefix := strings.TrimSuffix(backend.Path, "/")
		if u.Host == "" && u.Scheme == "" && strings.HasPrefix(u.Path, "/") && prefix != "" && (u.Path == prefix || strings.HasPrefix(u.Path, prefix+"/")) {
			u.Path = strings.TrimPrefix(u.Path, prefix)
			u.RawPath = ""
			if u.Path == "" {
				u.Path = "/"
			}
			resp.Header.Set("Location", u.String())
		}
		if u.IsAbs() || u.Host != "" {
			if strings.EqualFold(u.Host, backend.Host) && (u.Scheme == backend.Scheme || u.Scheme == "") {
				prefix := strings.TrimSuffix(backend.Path, "/")
				if prefix != "" && !strings.HasPrefix(u.Path, prefix+"/") && u.Path != prefix {
					return errApplicationDenied
				}
				u.Scheme = "https"
				u.Host = a.PublicHostname
				u.Path = strings.TrimPrefix(u.Path, prefix)
				u.RawPath = ""
				if u.Path == "" {
					u.Path = "/"
				}
				resp.Header.Set("Location", u.String())
			}
		}
	}
	return nil
}

// Every upgraded socket write retains a stall deadline after HTTP ownership ends.
type applicationWriteConn struct {
	net.Conn
	bytes *atomic.Int64
}

func (c applicationWriteConn) Write(b []byte) (int, error) {
	if e := c.Conn.SetWriteDeadline(time.Now().Add(30 * time.Second)); e != nil {
		return 0, e
	}
	n, e := c.Conn.Write(b)
	if c.bytes != nil {
		c.bytes.Add(int64(n))
	}
	return n, e
}
func (c applicationWriteConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return c.Conn.Close()
}

func applicationLaunchDocumentPath(path string) bool {
	parts := strings.Split(path, "/")
	return len(parts) == 4 && parts[1] == "applications" && parts[3] == "launch" && applicationSlug.MatchString(parts[2])
}

type applicationPortalDocumentWriter struct {
	http.ResponseWriter
	launch bool
}

func (w *applicationPortalDocumentWriter) headers() {
	w.Header().Set("Referrer-Policy", "strict-origin")
	if w.launch {
		w.Header().Set("Cache-Control", "no-store")
	}
}
func (w *applicationPortalDocumentWriter) WriteHeader(status int) {
	w.headers()
	w.ResponseWriter.WriteHeader(status)
}
func (w *applicationPortalDocumentWriter) Write(b []byte) (int, error) {
	w.headers()
	return w.ResponseWriter.Write(b)
}
func (w *applicationPortalDocumentWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func applicationPortalRedirect(origin, applicationID, path string) (string, error) {
	fixed, e := url.Parse(origin)
	if e != nil || fixed.Scheme != "https" || fixed.Host == "" || fixed.User != nil || (fixed.Path != "" && fixed.Path != "/") || fixed.RawQuery != "" || fixed.ForceQuery || fixed.Fragment != "" || !applicationSlug.MatchString(applicationID) {
		return "", errApplicationDenied
	}
	destination, e := applicationPath(path)
	if e != nil {
		return "", e
	}
	fixed.Path = "/applications/" + applicationID + "/launch"
	fixed.RawPath = ""
	fixed.RawQuery = url.Values{"path": []string{destination}}.Encode()
	return fixed.String(), nil
}
