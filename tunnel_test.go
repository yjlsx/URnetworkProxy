package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func trojanTestHeader(password string) []byte {
	sum := sha256.Sum224([]byte(password))
	h := []byte(hex.EncodeToString(sum[:]) + "\r\n")
	h = append(h, 1, 3, 11)
	h = append(h, "example.com"...)
	return append(h, 0, 80, '\r', '\n')
}

func TestTrojanRequestValidation(t *testing.T) {
	h := trojanTestHeader("test")
	host, port, err := readTrojanRequest(bytes.NewReader(h), "test")
	if err != nil || host != "example.com" || port != 80 {
		t.Fatalf("%s %d %v", host, port, err)
	}
	for _, bad := range [][]byte{h[:20], append([]byte("x"), h[1:]...), append(append([]byte{}, h[:58]...), 3, 1)} {
		if _, _, err := readTrojanRequest(bytes.NewReader(bad), "test"); err == nil {
			t.Fatal("accepted invalid or unsupported request")
		}
	}
}

// The SOCKS endpoint checks the actual destination and echoes payload after a
// full RFC1928 handshake. It deliberately does not depend on URnetwork access.
func tunnelTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	testSubscriptionConfig(t)
	t.Setenv("URNET_BIND_HOST", "127.0.0.1")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				var greeting [4]byte
				if _, err := io.ReadFull(conn, greeting[:]); err != nil {
					return
				}
				conn.Write([]byte{5, 0})
				var header [5]byte
				if _, err := io.ReadFull(conn, header[:]); err != nil {
					return
				}
				addr := make([]byte, int(header[4])+2)
				if _, err := io.ReadFull(conn, addr); err != nil || string(addr[:len(addr)-2]) != "example.com" || addr[len(addr)-1] != 80 {
					return
				}
				conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 80})
				io.Copy(conn, conn)
			}()
		}
	}()
	old := subscriptions
	subscriptions = &subscriptionManager{nodes: []subscriptionNode{{"Japan", ln.Addr().(*net.TCPAddr).Port}}}
	t.Cleanup(func() { subscriptions = old })
	server := httptest.NewTLSServer(http.HandlerFunc(NewServer().handleTunnel))
	t.Cleanup(server.Close)
	return server
}

func TestTunnelWebSocketForwardingAndAuthentication(t *testing.T) {
	server := tunnelTestServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	u := "wss" + strings.TrimPrefix(server.URL, "https") + tunnelPath(subscriptions.snapshot()[0].Port)
	for _, password := range []string{tunnelPassword("Japan"), "incorrect"} {
		ws, _, err := websocket.Dial(ctx, u, &websocket.DialOptions{HTTPClient: server.Client()})
		if err != nil {
			t.Fatal(err)
		}
		conn := websocket.NetConn(ctx, ws, websocket.MessageBinary)
		h := trojanTestHeader(password)
		// Header fragmented across frames, payload in the final header frame.
		conn.Write(h[:12])
		conn.Write(append(h[12:], []byte("hello tunnel")...))
		got := make([]byte, 12)
		_, err = io.ReadFull(conn, got)
		if password == "incorrect" {
			if err == nil {
				t.Fatal("unauthenticated connection forwarded")
			}
		} else if err != nil || string(got) != "hello tunnel" {
			t.Fatalf("forwarding: %q %v", got, err)
		}
		conn.Close()
	}
	before := tunnelPassword("Japan")
	if err := setPassword("changed"); err != nil {
		t.Fatal(err)
	}
	if before == tunnelPassword("Japan") {
		t.Fatal("tunnel credentials survived password rotation")
	}
}

func TestTunnelSubscriptionFormats(t *testing.T) {
	testSubscriptionConfig(t)
	nodes := []subscriptionNode{{"Japan", 10000}, {"Germany", 10001}}
	for _, format := range []string{"qx", "clash"} {
		body, err := renderTunnelSubscription(format, "https://panel.example.com", nodes)
		if err != nil || !strings.Contains(body, "/proxy/ws/10001") || !strings.Contains(body, tunnelPassword("Germany")) {
			t.Fatalf("%s: %v %s", format, err, body)
		}
		if format == "qx" && (!strings.Contains(body, "trojan=panel.example.com:443,") || !strings.Contains(body, "obfs=wss")) {
			t.Fatal(body)
		}
	}
	for _, base := range []string{"http://example.com", "https://example.com/path", "https://user:pass@example.com", "https://example.com?x=y"} {
		if _, err := renderTunnelSubscription("qx", base, nodes); err == nil {
			t.Fatalf("accepted %s", base)
		}
	}
}

// Optional interoperability check with an independently implemented client.
func TestTunnelMihomoInterop(t *testing.T) {
	bin := os.Getenv("URNET_TEST_MIHOMO")
	if bin == "" {
		t.Skip("set URNET_TEST_MIHOMO to run a real mihomo client")
	}
	server := tunnelTestServer(t)
	config, err := renderTunnelSubscription("clash", server.URL, subscriptions.snapshot())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	// Only the test TLS server has a self-signed certificate.
	config = strings.ReplaceAll(config, "skip-cert-verify: false", "skip-cert-verify: true")
	config = "mixed-port: " + strconv.Itoa(port) + "\nmode: rule\nlog-level: error\n" + config
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-d", dir, "-f", path)
	var logs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	var conn net.Conn
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		conn, err = socks5Dial(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), "", "", "example.com", 80, time.Second)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("mihomo: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write([]byte("mihomo echo"))
	b := make([]byte, 11)
	if _, err := io.ReadFull(conn, b); err != nil || string(b) != "mihomo echo" {
		t.Fatalf("mihomo forwarding: %q %v", b, err)
	}
}
