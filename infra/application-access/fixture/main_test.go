package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

func fixtureForTest(t *testing.T) (*fixture, *httptest.Server) {
	t.Helper()
	f := newFixture(credentials{Username: "synthetic-fixture", Password: token()})
	s := httptest.NewTLSServer(f)
	t.Cleanup(s.Close)
	return f, s
}
func decode(t *testing.T, r *http.Response) map[string]any {
	t.Helper()
	defer r.Body.Close()
	var data map[string]any
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		t.Fatal("fixture response could not be decoded")
	}
	return data
}
func waitZero(t *testing.T, value func() int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if value() == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("stream remained active after cancellation")
}

func TestNativeCookieLoginKeepsCSRFAndBasicIndependent(t *testing.T) {
	f, s := fixtureForTest(t)
	client := s.Client()
	client.Jar, _ = cookiejar.New(nil)
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	r, err := client.Get(s.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if !bytes.Contains(body, []byte("Native application login")) {
		t.Fatal("native form missing")
	}
	origin, _ := url.Parse(s.URL)
	var csrf string
	for _, c := range client.Jar.Cookies(origin) {
		if c.Name == "fixture_csrf" {
			csrf = c.Value
		}
	}
	for _, proof := range []string{"invalid", csrf} {
		r, err = client.PostForm(s.URL+"/login", url.Values{"username": {f.credentials.Username}, "password": {f.credentials.Password}, "csrf": {proof}})
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		want := http.StatusForbidden
		if proof == csrf {
			want = http.StatusSeeOther
		}
		if r.StatusCode != want {
			t.Fatalf("native login status %d, expected %d", r.StatusCode, want)
		}
		if proof == csrf {
			found := false
			for _, c := range r.Cookies() {
				if c.Name == "fixture_session" {
					found = true
					if !c.Secure || !c.HttpOnly || c.Domain != "" {
						t.Fatal("native cookie flags incorrect")
					}
				}
			}
			if !found {
				t.Fatal("native session cookie missing")
			}
		}
	}
	r, err = client.Get(s.URL + "/whoami")
	if err != nil {
		t.Fatal(err)
	}
	if decode(t, r)["username"] != f.credentials.Username {
		t.Fatal("native cookie identity missing")
	}
	r, err = client.Get(s.URL + "/basic")
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusUnauthorized {
		t.Fatal("cookie incorrectly satisfied native Basic")
	}
	req, _ := http.NewRequest(http.MethodGet, s.URL+"/basic", nil)
	req.SetBasicAuth(f.credentials.Username, f.credentials.Password)
	r, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if decode(t, r)["authentication"] != "basic" {
		t.Fatal("Basic identity missing")
	}
	r, err = client.PostForm(s.URL+"/logout", url.Values{"csrf": {csrf}})
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	r, err = client.Get(s.URL + "/whoami")
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusUnauthorized {
		t.Fatal("native logout retained session")
	}
}

func TestChunked64MiBUploadHasExactDigestAndCount(t *testing.T) {
	f, s := fixtureForTest(t)
	reader, writer := io.Pipe()
	defer reader.Close()
	sum := sha256.New()
	block := bytes.Repeat([]byte{0x6a}, 32<<10)
	go func() {
		for n := 0; n < 2048; n++ {
			if _, err := writer.Write(block); err != nil {
				return
			}
		}
		writer.Close()
	}()
	for n := 0; n < 2048; n++ {
		sum.Write(block)
	}
	req, _ := http.NewRequest(http.MethodPost, s.URL+"/upload", reader)
	r, err := s.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data := decode(t, r)
	if data["bytes"] != float64(64<<20) || data["content_length"] != float64(-1) || data["sha256"] != hex.EncodeToString(sum.Sum(nil)) {
		t.Fatal("streaming upload bytes/digest/framing mismatch")
	}
	if f.uploaded.Load() != 64<<20 {
		t.Fatal("upload byte counter mismatch")
	}
}

func TestSSEFlushesImmediatelyAndCleansUpCancellation(t *testing.T) {
	f, s := fixtureForTest(t)
	start := time.Now()
	r, err := s.Client().Get(s.URL + "/sse")
	if err != nil {
		t.Fatal(err)
	}
	first := make([]byte, len("id: 0\ndata: fixture-event-0\n\n"))
	if _, err = io.ReadFull(r.Body, first); err != nil {
		t.Fatal(err)
	}
	if string(first) != "id: 0\ndata: fixture-event-0\n\n" || time.Since(start) > time.Second {
		t.Fatal("SSE initial event was not immediately flushed")
	}
	r.Body.Close()
	waitZero(t, f.activeSSE.Load)
}

func TestWebSocketPreservesTextBinaryProtocolAndCleansUpClose(t *testing.T) {
	f := newFixture(credentials{Username: "synthetic-fixture", Password: token()})
	s := httptest.NewServer(f)
	defer s.Close()
	config, err := websocket.NewConfig("ws"+strings.TrimPrefix(s.URL, "http")+"/ws", s.URL)
	if err != nil {
		t.Fatal(err)
	}
	config.Protocol = []string{"veyport-fixture"}
	conn, err := websocket.DialConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if len(conn.Config().Protocol) != 1 || conn.Config().Protocol[0] != "veyport-fixture" {
		t.Fatal("WebSocket subprotocol changed")
	}
	for _, message := range []echoMessage{{[]byte("native text"), websocket.TextFrame}, {[]byte{0, 255, 42}, websocket.BinaryFrame}} {
		if err = echoCodec.Send(conn, message); err != nil {
			t.Fatal(err)
		}
		var reply echoMessage
		if err = echoCodec.Receive(conn, &reply); err != nil {
			t.Fatal(err)
		}
		if reply.kind != message.kind || !bytes.Equal(reply.data, message.data) {
			t.Fatal("WebSocket payload or frame type changed")
		}
	}
	conn.Close()
	waitZero(t, f.activeWS.Load)
}

func TestInspectionReturnsOnlyCredentialNames(t *testing.T) {
	_, s := fixtureForTest(t)
	canary := token()
	req, _ := http.NewRequest(http.MethodGet, s.URL+"/inspect?value="+canary, nil)
	req.Header.Set("Authorization", "Basic "+canary)
	req.AddCookie(&http.Cookie{Name: "native_cookie", Value: canary})
	r, err := s.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	raw, _ := io.ReadAll(r.Body)
	if bytes.Contains(raw, []byte(canary)) || !bytes.Contains(raw, []byte("native_cookie")) || !bytes.Contains(raw, []byte("Authorization")) {
		t.Fatal("inspection exposed values or lost names")
	}
}
