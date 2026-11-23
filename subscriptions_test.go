package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func testSubscriptionConfig(t *testing.T) {
	t.Helper()
	old := confFile
	confFile = filepath.Join(t.TempDir(), "urnetd.json")
	t.Cleanup(func() { confFile = old })
	t.Setenv("URNET_SOCKS_PASS", "test-password")
	if err := setPassword("test-panel-password"); err != nil {
		t.Fatal(err)
	}
}

func TestAllocateCountriesStableAndValidated(t *testing.T) {
	old := []subscriptionNode{{"Japan", 10000}, {"Germany", 10001}}
	nodes, err := allocateNodes([]string{"Germany", "Singapore", "Japan"}, old)
	if err != nil {
		t.Fatal(err)
	}
	want := []subscriptionNode{{"Germany", 10001}, {"Singapore", 10002}, {"Japan", 10000}}
	if !reflect.DeepEqual(nodes, want) {
		t.Fatalf("got %#v want %#v", nodes, want)
	}
	for _, countries := range [][]string{{"Japan", "Japan"}, {"bad\nname"}, {""}, {"1", "2", "3", "4", "5", "6", "7", "8", "9"}} {
		if _, err := allocateNodes(countries, nil); err == nil {
			t.Fatalf("accepted %q", countries)
		}
	}
}

func TestSubscriptionsPersistAndRender(t *testing.T) {
	testSubscriptionConfig(t)
	m := &subscriptionManager{}
	if err := m.configure([]string{"Japan", "United States"}); err != nil {
		t.Fatal(err)
	}
	reloaded := &subscriptionManager{}
	if err := reloaded.load(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(m.snapshot(), reloaded.snapshot()) {
		t.Fatal("configuration lost")
	}
	qx, err := renderSubscription("qx", "2001:db8::1", m.snapshot(), "user", "password")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(qx, "socks5=[2001:db8::1]:10000,") || !strings.Contains(qx, "tag=URnetwork-United States") || len(strings.Split(strings.TrimSpace(qx), "\n")) != 2 {
		t.Fatal(qx)
	}
	clash, err := renderSubscription("clash", "example.com", m.snapshot(), "user", "a\"b\nc")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(clash, "type: socks5") != 2 || !strings.Contains(clash, `password: "a\"b\nc"`) || !strings.Contains(clash, "port: 10001") {
		t.Fatal(clash)
	}
	if _, err := renderSubscription("qx", "example.com", m.snapshot(), "user", "bad,password"); err == nil {
		t.Fatal("accepted QX injection")
	}
	if _, err := renderSubscription("clash", "host\nproxies:", m.snapshot(), "user", "pass"); err == nil {
		t.Fatal("accepted host injection")
	}
	if err := m.configure(nil); err != nil {
		t.Fatal(err)
	}
	if err := reloaded.load(); err != nil {
		t.Fatal(err)
	}
	if len(reloaded.snapshot()) != 0 {
		t.Fatal("deleted countries reappeared")
	}
}

func TestSubscriptionHTTPTokenAndFormats(t *testing.T) {
	testSubscriptionConfig(t)
	old := subscriptions
	subscriptions = &subscriptionManager{nodes: []subscriptionNode{{"Japan", 10000}, {"Germany", 10001}}, workers: map[string]*Server{}}
	t.Cleanup(func() { subscriptions = old })
	s := NewServer()
	token := subToken()
	for _, tc := range []struct {
		path     string
		status   int
		contains string
	}{
		{"/sub/invalid.yaml?host=example.com", 403, ""},
		{"/sub/" + token + ".yaml?host=example.com", 200, "port: 10001"},
		{"/sub/" + token + ".conf?host=2001:db8::1", 200, "socks5=[2001:db8::1]:10001"},
		{"/sub/" + token + ".conf?transport=wss&base=https%3A%2F%2Fpanel.example.com", 200, "trojan=panel.example.com:443,"},
		{"/sub/" + token + ".yaml?transport=wss&base=https%3A%2F%2Fpanel.example.com", 200, "network: ws"},
		{"/sub/invalid.conf?transport=wss&base=https%3A%2F%2Fpanel.example.com", 403, ""},
		{"/sub/" + token + ".conf?transport=wss&base=http%3A%2F%2Fpanel.example.com", 400, ""},
		{"/sub/" + token + ".yaml?host=bad%0Ahost", 400, ""},
	} {
		rr := httptest.NewRecorder()
		s.handleSub(rr, httptest.NewRequest("GET", tc.path, nil))
		if rr.Code != tc.status || !strings.Contains(rr.Body.String(), tc.contains) {
			t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
		}
	}
	if err := setPassword("changed"); err != nil {
		t.Fatal(err)
	}
	if checkSubToken(token) {
		t.Fatal("old token survived rotation")
	}
	if err := saveConf(savedConf{}); err != nil {
		t.Fatal(err)
	}
	if checkSubToken(subToken()) {
		t.Fatal("subscription enabled without password")
	}
}

// A real child process/listener, without URnetwork credentials or network access.
func TestMain(m *testing.M) {
	if os.Getenv("URNET_TEST_WORKER") == "1" {
		addr, country := "", ""
		for i := 1; i+1 < len(os.Args); i++ {
			switch os.Args[i] {
			case "--addr":
				addr = os.Args[i+1]
			case "--country":
				country = os.Args[i+1]
			}
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			os.Exit(2)
		}
		fmt.Println("socks5 server is listening")
		for {
			c, err := ln.Accept()
			if err != nil {
				os.Exit(0)
			}
			fmt.Fprintln(c, country)
			c.Close()
		}
	}
	os.Exit(m.Run())
}

func TestCountryWorkersIndependentAndRetired(t *testing.T) {
	testSubscriptionConfig(t)
	oldBin, oldAuth := binPath, authState
	binPath, _ = os.Executable()
	authState = filepath.Join(t.TempDir(), "auth_state")
	if err := os.WriteFile(authState, []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { binPath = oldBin; authState = oldAuth })
	t.Setenv("URNET_TEST_WORKER", "1")
	t.Setenv("URNET_BIND_HOST", "127.0.0.1")
	workers := []*Server{NewServer(), NewServer()}
	t.Cleanup(func() {
		for _, w := range workers {
			retireWorker(w)
		}
	})
	for i, w := range workers {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		w.port = ln.Addr().(*net.TCPAddr).Port
		ln.Close()
		w.isolated = true
		if err := w.startLocked([]string{"Japan", "Germany"}[i]); err != nil {
			t.Fatal(err)
		}
	}
	assertCountry := func(w *Server, want string) {
		t.Helper()
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", w.port), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 100)
		n, _ := c.Read(buf)
		if strings.TrimSpace(string(buf[:n])) != want {
			t.Fatalf("wrong country: %q", buf[:n])
		}
	}
	assertCountry(workers[0], "Japan")
	assertCountry(workers[1], "Germany")
	retireWorker(workers[0])
	workers[0].Switch("Japan")
	workers[0].mu.Lock()
	running := workers[0].running
	workers[0].mu.Unlock()
	if running {
		t.Fatal("retired worker restarted")
	}
	assertCountry(workers[1], "Germany")
	if loadConf().Country != "" {
		t.Fatal("worker overwrote primary country")
	}
}

func TestSubscriptionStatusDoesNotLeakPassword(t *testing.T) {
	testSubscriptionConfig(t)
	t.Setenv("URNET_PUBLIC_HOST", "proxy.example.com")
	t.Setenv("URNET_BIND_HOST", "127.0.0.1")
	old := subscriptions
	worker := NewServer()
	worker.running, worker.ready = true, true
	worker.probeErr = "upstream timed out"
	worker.exitIP = "198.51.100.7"
	worker.exitVerifiedAt = time.Date(2026, 11, 23, 8, 0, 0, 0, time.UTC)
	subscriptions = &subscriptionManager{
		nodes:   []subscriptionNode{{"Japan", 10000}},
		workers: map[string]*Server{"Japan": worker},
	}
	t.Cleanup(func() { subscriptions = old })
	rr := httptest.NewRecorder()
	NewServer().handleSubscriptions(rr, httptest.NewRequest("GET", "/api/subscriptions", nil))
	var result map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rr.Body.String(), "test-password") {
		t.Fatal("password leaked")
	}
	if result["nodeHost"] != "proxy.example.com" || result["bindHost"] != "127.0.0.1" {
		t.Fatal("missing configured connection addresses")
	}
	node := result["nodes"].([]any)[0].(map[string]any)
	if node["running"] != true || node["ready"] != true || node["probeError"] != "upstream timed out" || node["exitIP"] != "198.51.100.7" || node["exitVerifiedAt"] == nil {
		t.Fatal("process status must preserve failed upstream probe")
	}
}

func TestExportRunningNodeLinks(t *testing.T) {
	testSubscriptionConfig(t)
	old := subscriptions
	active, stopped, busy := NewServer(), NewServer(), NewServer()
	active.running, active.ready = true, true
	busy.running, busy.busy = true, true
	unready := NewServer()
	unready.running = true
	subscriptions = &subscriptionManager{
		nodes:   []subscriptionNode{{"Japan", 10000}, {"Germany", 10001}, {"Singapore", 10002}, {"France", 10003}},
		workers: map[string]*Server{"Japan": active, "Germany": stopped, "Singapore": busy, "France": unready},
	}
	t.Cleanup(func() { subscriptions = old })
	for _, query := range []string{"transport=wss&base=https%3A%2F%2Fpanel.example.com", "host=2001:db8::1"} {
		rr := httptest.NewRecorder()
		NewServer().handleSubscriptionLinks(rr, httptest.NewRequest("GET", "/api/subscription-links?"+query, nil))
		var result struct {
			Nodes []struct{ Country, URI, QX string }
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil || rr.Code != 200 {
			t.Fatalf("%d %s %v", rr.Code, rr.Body.String(), err)
		}
		if len(result.Nodes) != 1 || result.Nodes[0].Country != "Japan" {
			t.Fatal("exported stopped or busy nodes")
		}
		n := result.Nodes[0]
		u, err := url.Parse(n.URI)
		if err != nil || u.Fragment != "URnetwork-Japan" {
			t.Fatalf("invalid URI: %s", n.URI)
		}
		if strings.Contains(query, "wss") {
			if u.Scheme != "trojan" || u.Host != "panel.example.com:443" || u.User.Username() != tunnelPassword("Japan") || u.Query().Get("path") != "/proxy/ws/10000" || !strings.Contains(n.QX, "obfs=wss") {
				t.Fatal("incorrect tunnel URI or QX configuration")
			}
		} else if u.Scheme != "socks5" || u.Host != "[2001:db8::1]:10000" || !strings.Contains(n.QX, "socks5=[2001:db8::1]:10000") {
			t.Fatal("incorrect direct URI")
		}
	}
	active.running = false
	rr := httptest.NewRecorder()
	NewServer().handleSubscriptionLinks(rr, httptest.NewRequest("GET", "/api/subscription-links", nil))
	if strings.TrimSpace(rr.Body.String()) != `{"nodes":[]}` {
		t.Fatal("expected empty list when no nodes are active")
	}
}
