// *************************************************************************
//
// REFRACTION POINT CONFIDENTIAL
// __________________
//
//  Copyright 2018 Refraction Point Inc.
//  All Rights Reserved.
//
// NOTICE:  All information contained herein is, and remains
// the property of Refraction Point Inc. and its suppliers,
// if any.  The intellectual and technical concepts contained
// herein are proprietary to Refraction Point Inc
// and its suppliers and may be covered by U.S. and Foreign Patents,
// patents in process, and are protected by trade secret or copyright law.
// Dissemination of this information or reproduction of this material
// is strictly forbidden unless prior written permission is obtained
// from Refraction Point Inc.
//

package arl

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func drain(ch chan Content) []Content {
	out := []Content{}
	for c := range ch {
		out = append(out, c)
	}
	return out
}

func testKeyPEM(t *testing.T) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(t, k)}))
}

func mustPKCS8(t *testing.T, k *rsa.PrivateKey) []byte {
	b, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func gcsARL(t *testing.T, key any) string {
	t.Helper()
	b, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("[gcs,some-bucket/prefix,gaia,%s]", base64.StdEncoding.EncodeToString(b))
}

func saKey(t *testing.T, extra map[string]any) map[string]any {
	k := map[string]any{
		"type":           "service_account",
		"project_id":     "p",
		"private_key_id": "kid",
		"private_key":    testKeyPEM(t),
		"client_email":   "sa@p.iam.gserviceaccount.com",
		"client_id":      "1",
		"auth_uri":       "https://accounts.google.com/o/oauth2/auth",
		"token_uri":      "https://oauth2.googleapis.com/token",
	}
	for n, v := range extra {
		if v == nil {
			delete(k, n)
		} else {
			k[n] = v
		}
	}
	return k
}

// A request-counting server stands in for anything a credential could make us
// contact; none of the rejected credentials may reach it.
func countingServer(hits *atomic.Int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(500)
	}))
}

func TestGCSRejectsNonServiceAccountCredentials(t *testing.T) {
	hits := atomic.Int32{}
	srv := countingServer(&hits)
	defer srv.Close()

	secret := t.TempDir() + "/secret.txt"
	if err := writeFile(secret, "super-secret"); err != nil {
		t.Fatal(err)
	}

	cases := map[string]map[string]any{
		"external_account file source": {
			"type":               "external_account",
			"audience":           "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/q",
			"subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
			"token_url":          srv.URL,
			"credential_source":  map[string]any{"file": secret},
		},
		"external_account url source": {
			"type":               "external_account",
			"audience":           "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/q",
			"subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
			"token_url":          srv.URL,
			"credential_source":  map[string]any{"url": srv.URL},
		},
		"impersonated_service_account": {
			"type":                              "impersonated_service_account",
			"service_account_impersonation_url": srv.URL,
			"source_credentials":                map[string]any{"type": "authorized_user"},
		},
		"authorized_user": {
			"type":          "authorized_user",
			"client_id":     "x",
			"client_secret": "y",
			"refresh_token": "z",
		},
		"external_account_authorized_user": {
			"type":          "external_account_authorized_user",
			"token_url":     srv.URL,
			"refresh_token": "z",
		},
		"gdch_service_account": {
			"type":        "gdch_service_account",
			"token_uri":   srv.URL,
			"private_key": testKeyPEM(t),
		},
		"no type": {
			"private_key":  testKeyPEM(t),
			"client_email": "a@b",
		},
		"service_account with foreign token_uri": saKey(t, map[string]any{"token_uri": srv.URL}),
		"service_account with lookalike token_uri": saKey(t, map[string]any{
			"token_uri": "https://oauth2.googleapis.com.evil.example/token",
		}),
		"service_account with foreign universe_domain": saKey(t, map[string]any{"universe_domain": "evil.example"}),
		"service_account without private key":          saKey(t, map[string]any{"private_key": nil}),
	}

	for name, key := range cases {
		t.Run(name, func(t *testing.T) {
			a, err := NewARL(gcsARL(t, key), 1024*1024, 2)
			if err != nil {
				t.Fatalf("NewARL: %v", err)
			}
			done := make(chan error, 1)
			go func() {
				_, err := a.Fetch()
				done <- err
			}()
			select {
			case err := <-done:
				if !errors.Is(err, ErrorInvalidCredentials) {
					t.Fatalf("expected ErrorInvalidCredentials, got %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("fetch did not return")
			}
		})
	}

	if n := hits.Load(); n != 0 {
		t.Errorf("rejected credentials still caused %d requests", n)
	}
}

func TestSanitizeServiceAccountKey(t *testing.T) {
	// Real keys, with the current and the legacy token endpoints, are kept.
	for _, tokenURI := range []any{
		"https://oauth2.googleapis.com/token",
		"https://accounts.google.com/o/oauth2/token",
		nil,
	} {
		b, _ := json.Marshal(saKey(t, map[string]any{"token_uri": tokenURI, "universe_domain": "googleapis.com"}))
		out, err := sanitizeServiceAccountKey(b)
		if err != nil {
			t.Fatalf("token_uri %v: %v", tokenURI, err)
		}
		var m map[string]any
		if err := json.Unmarshal(out, &m); err != nil {
			t.Fatal(err)
		}
		if m["type"] != "service_account" || m["client_email"] != "sa@p.iam.gserviceaccount.com" || m["private_key"] == "" {
			t.Errorf("sanitized key lost required fields: %v", m)
		}
	}

	// Only the service account fields survive; nothing else can reach the
	// credential parser, whatever the key casing tricks.
	raw := `{"type":"external_account","TYPE":"service_account","private_key":"k","client_email":"e",
		"credential_source":{"file":"/etc/hostname"},"token_url":"https://x","service_account_impersonation_url":"https://x",
		"source_credentials":{"type":"external_account"},"universe_domain":"googleapis.com"}`
	out, err := sanitizeServiceAccountKey([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	for k := range m {
		switch k {
		case "type", "private_key", "client_email":
		default:
			t.Errorf("unexpected field %q survived sanitization", k)
		}
	}
	if m["type"] != "service_account" {
		t.Errorf("type = %v", m["type"])
	}

	// ...and the same JSON with the type resolving to anything else is out.
	if _, err := sanitizeServiceAccountKey([]byte(strings.Replace(raw, `"TYPE":"service_account"`, `"TYPE":"external_account"`, 1))); err == nil {
		t.Error("external_account accepted")
	}
	if _, err := sanitizeServiceAccountKey([]byte("not json")); err == nil {
		t.Error("garbage accepted")
	}
}

// fakeGCS serves just enough of the storage JSON API (through the storage
// client's emulator mode) to exercise listing and downloading.
func fakeGCS(t *testing.T, objects map[string][]byte, listStatus int) {
	t.Helper()
	fakeGCSStalling(t, objects, listStatus, nil)
}

// fakeGCSStalling is fakeGCS where downloads of the named objects never
// complete.
func fakeGCSStalling(t *testing.T, objects map[string][]byte, listStatus int, stall map[string]bool) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if listStatus != 0 && strings.HasSuffix(r.URL.Path, "/o") {
			http.Error(w, `{"error":{"code":403,"message":"forbidden"}}`, listStatus)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/o") {
			items := []map[string]any{}
			for n, d := range objects {
				items = append(items, map[string]any{"name": n, "bucket": "some-bucket", "size": fmt.Sprint(len(d))})
			}
			json.NewEncoder(w).Encode(map[string]any{"kind": "storage#objects", "items": items})
			return
		}
		for n, d := range objects {
			if strings.HasSuffix(r.URL.Path, "/"+n) {
				if stall[n] {
					w.Write(d[:1])
					w.(http.Flusher).Flush()
					<-r.Context().Done()
					return
				}
				w.Write(d)
				return
			}
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("STORAGE_EMULATOR_HOST", srv.Listener.Addr().String())
}

func TestGCSListingErrorIsReturned(t *testing.T) {
	fakeGCS(t, nil, http.StatusForbidden)
	a, err := NewARL(gcsARL(t, saKey(t, nil)), 1024*1024, 2)
	if err != nil {
		t.Fatal(err)
	}
	type res struct {
		ch  chan Content
		err error
	}
	done := make(chan res, 1)
	go func() {
		ch, err := a.Fetch()
		done <- res{ch, err}
	}()
	select {
	case r := <-done:
		if r.err == nil {
			t.Fatal("listing failure produced no error")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Fetch did not return on a listing error")
	}
}

func TestGCSFetch(t *testing.T) {
	fakeGCS(t, map[string][]byte{"prefix/a.txt": []byte("hello"), "prefix/b.txt": []byte("world")}, 0)
	a, err := NewARL(gcsARL(t, saKey(t, nil)), 1024, 2)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := a.Fetch()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for c := range ch {
		if c.Error != nil {
			t.Fatalf("unexpected error: %v", c.Error)
		}
		got[c.FilePath] = string(c.Data)
	}
	if len(got) != 2 || got["gcs://some-bucket/prefix/a.txt"] != "hello" || got["gcs://some-bucket/prefix/b.txt"] != "world" {
		t.Errorf("unexpected content: %v", got)
	}
}

func TestGCSMaxSize(t *testing.T) {
	fakeGCS(t, map[string][]byte{"prefix/a.bin": bytes.Repeat([]byte("x"), 2048)}, 0)
	a, err := NewARL(gcsARL(t, saKey(t, nil)), 1024, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Fetch(); !errors.Is(err, ErrorResourceTooLarge) {
		t.Errorf("expected ErrorResourceTooLarge, got %v", err)
	}
}

// allowLoopback exempts the test servers from the destination guard while
// leaving the rest of the policy in place.
func allowLoopback(t *testing.T) Option {
	return WithAllowedNetworks(netip.MustParsePrefix("127.0.0.1/32"))
}

func TestHTTPMaxSize(t *testing.T) {
	big := bytes.Repeat([]byte("a"), 64*1024)
	withLength := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(big)
	}))
	defer withLength.Close()
	// Chunked and never ending: only the read limit (or the client
	// giving up) can stop it.
	endless := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fl := w.(http.Flusher)
		for {
			if _, err := w.Write(big); err != nil {
				return
			}
			fl.Flush()
		}
	}))
	defer endless.Close()

	for name, srv := range map[string]*httptest.Server{"content-length": withLength, "chunked": endless} {
		t.Run(name, func(t *testing.T) {
			a, err := NewARL("[http,"+srv.Listener.Addr().String()+"/x]", 16*1024, 2, allowLoopback(t))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := a.Fetch(); !errors.Is(err, ErrorResourceTooLarge) {
				t.Errorf("expected ErrorResourceTooLarge, got %v", err)
			}
		})
	}

	// Within the limit still works.
	a, _ := NewARL("[http,"+withLength.Listener.Addr().String()+"/x]", 1024*1024, 2, allowLoopback(t))
	ch, err := a.Fetch()
	if err != nil {
		t.Fatal(err)
	}
	if cs := drain(ch); len(cs) != 1 || len(cs[0].Data) != len(big) || cs[0].Error != nil {
		t.Errorf("unexpected content: %+v", cs)
	}
}

func makeZip(t *testing.T, files map[string][]byte) []byte {
	b := bytes.Buffer{}
	zw := zip.NewWriter(&b)
	for n, d := range files {
		w, err := zw.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(d)
	}
	zw.Close()
	return b.Bytes()
}

func TestArchiveExpansionIsBounded(t *testing.T) {
	// ~4 MB expanded, a few KB on the wire.
	bomb := makeZip(t, map[string][]byte{
		"a": bytes.Repeat([]byte{0}, 2*1024*1024),
		"b": bytes.Repeat([]byte{0}, 2*1024*1024),
	})
	if len(bomb) > 64*1024 {
		t.Fatalf("test archive not compressible: %d", len(bomb))
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(bomb) }))
	defer srv.Close()

	a, _ := NewARL("[http,"+srv.Listener.Addr().String()+"/x.zip]", 1024*1024, 2, allowLoopback(t))
	ch, err := a.Fetch()
	if err != nil {
		t.Fatal(err)
	}
	cs := drain(ch)
	tooLarge := false
	total := 0
	for _, c := range cs {
		total += len(c.Data)
		if errors.Is(c.Error, ErrorResourceTooLarge) {
			tooLarge = true
		}
	}
	if !tooLarge {
		t.Error("expanded size over maxSize produced no error")
	}
	if total > 1024*1024+1 {
		t.Errorf("expanded %d bytes past the limit", total)
	}

	// A legitimate archive within the limit is expanded fully.
	ok := makeZip(t, map[string][]byte{"one.txt": []byte("1"), "two.txt": []byte("22")})
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(ok) }))
	defer srv2.Close()
	a, _ = NewARL("[http,"+srv2.Listener.Addr().String()+"/x.zip]", 1024*1024, 2, allowLoopback(t))
	ch, _ = a.Fetch()
	cs = drain(ch)
	if len(cs) != 2 {
		t.Fatalf("unexpected number of files: %d", len(cs))
	}
	for _, c := range cs {
		if c.Error != nil {
			t.Errorf("unexpected error: %v", c.Error)
		}
	}
}

func TestHTTPTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("start"))
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)

	a, _ := NewARL("[http,"+srv.Listener.Addr().String()+"/x]", 1024, 2, allowLoopback(t), WithTimeout(300*time.Millisecond))
	start := time.Now()
	if _, err := a.Fetch(); err == nil {
		t.Error("stalled body did not produce an error")
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("timeout not enforced, took %v", time.Since(start))
	}
}

func okServer(hits *atomic.Int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("secret-internal-data"))
	}))
}

func TestHTTPRefusesNonPublicDestinations(t *testing.T) {
	hits := atomic.Int32{}
	srv := okServer(&hits)
	defer srv.Close()
	addr := srv.Listener.Addr().String()
	_, port, _ := net.SplitHostPort(addr)

	for name, arl := range map[string]string{
		"literal loopback ip":   "[http," + addr + "/x]",
		"loopback via hostname": "[http,localhost:" + port + "/x]",
		"https shortcut":        "https://" + addr + "/x",
		"link local metadata":   "[http,169.254.169.254/computeMetadata/v1/]",
		"metadata hostname":     "[http,metadata.google.internal/computeMetadata/v1/]",
		"private":               "[http,10.0.0.1/x]",
		"ipv6 loopback":         "[http,[::1]:" + port + "/x]",
	} {
		t.Run(name, func(t *testing.T) {
			a, err := NewARL(arl, 1024, 2, WithTimeout(10*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			_, err = a.Fetch()
			if !errors.Is(err, ErrorDestinationNotAllowed) {
				// metadata.google.internal does not resolve outside of GCP,
				// a resolution failure is as good a refusal.
				var dnsErr *net.DNSError
				if !(name == "metadata hostname" && errors.As(err, &dnsErr)) {
					t.Errorf("expected ErrorDestinationNotAllowed, got %v", err)
				}
			}
		})
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("guarded fetches reached the server %d times", n)
	}

	// Trusted callers can opt in.
	a, _ := NewARL("[http,"+addr+"/x]", 1024, 2, WithAllowPrivateNetworks())
	ch, err := a.Fetch()
	if err != nil {
		t.Fatalf("opt-in fetch failed: %v", err)
	}
	if cs := drain(ch); len(cs) != 1 || string(cs[0].Data) != "secret-internal-data" {
		t.Errorf("unexpected content: %+v", cs)
	}
}

func TestHTTPRedirectToNonPublicDestinationRefused(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skipf("cannot bind 127.0.0.2: %v", err)
	}
	hits := atomic.Int32{}
	internal := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("internal"))
	}))
	internal.Listener.Close()
	internal.Listener = l
	internal.Start()
	defer internal.Close()

	// The "public" hop is the only exempted destination, it bounces to the
	// internal one.
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal.URL+"/x", http.StatusFound)
	}))
	defer redirector.Close()

	a, _ := NewARL("[http,"+redirector.Listener.Addr().String()+"/x]", 1024, 2, allowLoopback(t))
	_, err = a.Fetch()
	if !errors.Is(err, ErrorDestinationNotAllowed) {
		t.Errorf("expected ErrorDestinationNotAllowed, got %v", err)
	}
	if hits.Load() != 0 {
		t.Error("redirect target was contacted")
	}
}

func TestOTXKeyNotForwardedToOtherHost(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skipf("cannot bind 127.0.0.2: %v", err)
	}
	seen := make(chan string, 1)
	other := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("X-OTX-API-KEY")
		w.Write([]byte("ok"))
	}))
	other.Listener.Close()
	other.Listener = l
	other.Start()
	defer other.Close()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-OTX-API-KEY") != "k" {
			t.Error("api key not sent to the original host")
		}
		http.Redirect(w, r, other.URL+"/x", http.StatusFound)
	}))
	defer first.Close()

	a, _ := NewARL("[http,"+first.Listener.Addr().String()+"/x,otx,k]", 1024, 2, WithAllowedNetworks(netip.MustParsePrefix("127.0.0.0/24")))
	ch, err := a.Fetch()
	if err != nil {
		t.Fatal(err)
	}
	drain(ch)
	if k := <-seen; k != "" {
		t.Errorf("api key forwarded to another host: %q", k)
	}
}

func TestRedirectDowngradeRefused(t *testing.T) {
	from, _ := http.NewRequest("GET", "https://a.example/x", nil)
	to, _ := http.NewRequest("GET", "http://a.example/x", nil)
	if err := checkRedirect(to, []*http.Request{from}); !errors.Is(err, ErrorInsecureRedirect) {
		t.Errorf("expected ErrorInsecureRedirect, got %v", err)
	}
}

func TestIsBlockedAddr(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.1.2.3", "::1", "0.0.0.0", "::",
		"169.254.169.254", "169.254.0.1", "fe80::1", "fd00:ec2::254",
		"10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "fc00::1",
		"100.64.0.1", "100.127.255.255", "224.0.0.1", "255.255.255.255", "240.0.0.1",
		"::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:10.0.0.1",
		"64:ff9b::a9fe:a9fe", "64:ff9b::7f00:1", "2002:a9fe:a9fe::1", "2002:7f00:1::1",
		"198.18.0.1", "2001::1", "192.88.99.1", "2001:2::1", "2001:10::1",
	}
	for _, s := range blocked {
		if !isBlockedAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s should be blocked", s)
		}
	}
	allowed := []string{
		"8.8.8.8", "1.1.1.1", "140.82.112.3", "172.32.0.1", "172.15.255.255",
		"100.128.0.1", "2606:4700:4700::1111", "2001:4860:4860::8888",
		"::ffff:8.8.8.8", "64:ff9b::808:808",
	}
	for _, s := range allowed {
		if isBlockedAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s should be allowed", s)
		}
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0600)
}

func TestSizeAndConcurrencyClamps(t *testing.T) {
	// A pathological maxSize cannot push size arithmetic out of int64
	// range, and a pathological maxConcurrent cannot spawn an
	// unbounded number of workers.
	a, err := NewARL("[https,example.com/x]", 1<<62, 1<<40)
	if err != nil {
		t.Fatal(err)
	}
	if a.maxSize > uint64(math.MaxInt64/2) {
		t.Errorf("maxSize not clamped: %d", a.maxSize)
	}
	if a.maxConcurrent > maxConcurrentLimit {
		t.Errorf("maxConcurrent not clamped: %d", a.maxConcurrent)
	}

	// Zero values select generous defaults, never unbounded fetches.
	a, err = NewARL("[https,example.com/x]", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if a.maxSize != defaultMaxSize {
		t.Errorf("default maxSize = %d, want %d", a.maxSize, defaultMaxSize)
	}
	if a.maxConcurrent != 1 {
		t.Errorf("default maxConcurrent = %d, want 1", a.maxConcurrent)
	}
}

func TestAbandonedMultiplexIsBounded(t *testing.T) {
	// A consumer that walks away mid-expansion holds the expansion
	// goroutine for at most the deadline.
	archive := makeZip(t, map[string][]byte{"a": []byte("aa"), "b": []byte("bb")})
	ch := multiplexContent(Content{Data: archive}, 1024*1024, 50*time.Millisecond)
	// Read nothing: the expansion blocks on the second entry.
	expired := time.After(10 * time.Second)
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				// The channel closed even though we never
				// drained it.
				return
			}
		case <-expired:
			t.Fatal("abandoned multiplex did not give up after its deadline")
		}
	}
}

func shortGrace(t *testing.T) {
	old := abandonGrace
	abandonGrace = 5 * time.Second
	t.Cleanup(func() { abandonGrace = old })
}

// A fetch that runs out of time must say so: closing the channel normally
// would look like a complete (possibly empty) result.
func TestGCSDeadlineIsReported(t *testing.T) {
	shortGrace(t)
	fakeGCSStalling(t, map[string][]byte{
		"prefix/fast.txt": []byte("fast"),
		"prefix/slow.txt": []byte("slow"),
	}, 0, map[string]bool{"prefix/slow.txt": true})

	for i := 0; i < 8; i++ {
		a, err := NewARL(gcsARL(t, saKey(t, nil)), 1024, 2, WithTimeout(400*time.Millisecond))
		if err != nil {
			t.Fatal(err)
		}
		ch, err := a.Fetch()
		if err != nil {
			t.Fatal(err)
		}
		sawError, sawFast := false, false
		for c := range ch {
			if c.Error != nil {
				sawError = true
			} else if c.FilePath == "gcs://some-bucket/prefix/fast.txt" {
				sawFast = true
			}
		}
		if !sawError {
			t.Fatalf("attempt %d: stalled download closed the channel without an error", i)
		}
		if !sawFast {
			t.Fatalf("attempt %d: completed object was not delivered", i)
		}
	}
}

func TestGCSSlowConsumerGetsIncompleteError(t *testing.T) {
	shortGrace(t)
	fakeGCS(t, map[string][]byte{"prefix/a.txt": []byte("a"), "prefix/b.txt": []byte("b")}, 0)
	a, err := NewARL(gcsARL(t, saKey(t, nil)), 1024, 1, WithTimeout(500*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	ch, err := a.Fetch()
	if err != nil {
		t.Fatal(err)
	}
	// Not reading until after the deadline.
	time.Sleep(1200 * time.Millisecond)
	var last Content
	for c := range ch {
		last = c
	}
	if !errors.Is(last.Error, context.DeadlineExceeded) {
		t.Errorf("expected the last message to report the deadline, got %v", last.Error)
	}
}

func TestMultiplexDeadlineIsReported(t *testing.T) {
	shortGrace(t)
	z := makeZip(t, map[string][]byte{"one": []byte("1"), "two": []byte("2"), "three": []byte("3")})
	ch := multiplexContent(Content{Data: z}, 1024*1024, 300*time.Millisecond)
	time.Sleep(900 * time.Millisecond)
	var last Content
	for c := range ch {
		last = c
	}
	if !errors.Is(last.Error, context.DeadlineExceeded) {
		t.Errorf("expected the last message to report the deadline, got %v", last.Error)
	}
}

// net/http rebuilds the request headers of every hop from the original
// request, the key must stay out of all hops that leave the original host.
func TestOTXKeyNotForwardedOnLaterHops(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skipf("cannot bind 127.0.0.2: %v", err)
	}
	seen := make(chan string, 4)
	other := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.URL.Path + "=" + r.Header.Get("X-OTX-API-KEY")
		if r.URL.Path == "/hop1" {
			http.Redirect(w, r, "/hop2", http.StatusFound)
			return
		}
		w.Write([]byte("ok"))
	}))
	other.Listener.Close()
	other.Listener = l
	other.Start()
	defer other.Close()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/hop1", http.StatusFound)
	}))
	defer first.Close()

	a, _ := NewARL("[http,"+first.Listener.Addr().String()+"/x,otx,k]", 1024, 2, WithAllowedNetworks(netip.MustParsePrefix("127.0.0.0/24")))
	ch, err := a.Fetch()
	if err != nil {
		t.Fatal(err)
	}
	drain(ch)
	close(seen)
	n := 0
	for s := range seen {
		n++
		if !strings.HasSuffix(s, "=") {
			t.Errorf("api key forwarded to another host: %s", s)
		}
	}
	if n != 2 {
		t.Errorf("expected 2 requests to the other host, got %d", n)
	}
}
