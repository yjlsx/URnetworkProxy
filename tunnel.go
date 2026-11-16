package main

// Trojan TCP over WebSocket. HTTPS is terminated by the reverse proxy/Tunnel;
// this handler only connects through an explicitly selected country's SOCKS5.
import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
)

func tunnelPassword(country string) string {
	m := hmac.New(sha256.New, sessionKey(loadConf()))
	m.Write([]byte("urnetd-trojan-ws-v1:" + country))
	return hex.EncodeToString(m.Sum(nil))
}

func tunnelPath(port int) string { return "/proxy/ws/" + strconv.Itoa(port) }

func readTrojanRequest(conn io.Reader, password string) (string, int, error) {
	var header [58]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return "", 0, err
	}
	sum := sha256.Sum224([]byte(password))
	want := hex.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare(header[:56], []byte(want)) != 1 || string(header[56:]) != "\r\n" {
		return "", 0, fmt.Errorf("invalid authentication")
	}
	var command [2]byte
	if _, err := io.ReadFull(conn, command[:]); err != nil {
		return "", 0, err
	}
	if command[0] != 1 { // CONNECT only; never advertise UDP.
		return "", 0, fmt.Errorf("only TCP CONNECT is supported")
	}
	var address []byte
	switch command[1] {
	case 1:
		address = make([]byte, 4)
	case 4:
		address = make([]byte, 16)
	case 3:
		var size [1]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return "", 0, err
		}
		if size[0] == 0 {
			return "", 0, fmt.Errorf("empty destination")
		}
		address = make([]byte, int(size[0]))
	default:
		return "", 0, fmt.Errorf("invalid address type")
	}
	if _, err := io.ReadFull(conn, address); err != nil {
		return "", 0, err
	}
	var tail [4]byte
	if _, err := io.ReadFull(conn, tail[:]); err != nil {
		return "", 0, err
	}
	port := int(binary.BigEndian.Uint16(tail[:2]))
	if port == 0 || string(tail[2:]) != "\r\n" {
		return "", 0, fmt.Errorf("invalid destination")
	}
	if command[1] == 3 {
		return string(address), port, nil
	}
	return net.IP(address).String(), port, nil
}

func (s *Server) handleTunnel(w http.ResponseWriter, r *http.Request) {
	c := loadConf()
	if c.PassHash == "" || c.Salt == "" {
		http.Error(w, "set a panel password first", http.StatusForbidden)
		return
	}
	port, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/proxy/ws/"))
	if err != nil || r.Method != "GET" {
		http.NotFound(w, r)
		return
	}
	var country string
	for _, node := range subscriptions.snapshot() {
		if node.Port == port {
			country = node.Country
			break
		}
	}
	if country == "" {
		http.NotFound(w, r)
		return
	}
	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer ws.CloseNow()
	ws.SetReadLimit(1 << 20)
	conn := websocket.NetConn(r.Context(), ws, websocket.MessageBinary)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	host, targetPort, err := readTrojanRequest(conn, tunnelPassword(country))
	if err != nil {
		return
	}
	bind := env("URNET_BIND_HOST", "0.0.0.0")
	if bind == "0.0.0.0" {
		bind = "127.0.0.1"
	} else if bind == "::" {
		bind = "::1"
	}
	upstream, err := socks5Dial(net.JoinHostPort(bind, strconv.Itoa(port)), socksUser, socksPassword(), host, targetPort, 15*time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()
	conn.SetDeadline(time.Time{})
	done := make(chan struct{})
	go func() {
		io.Copy(upstream, conn)
		upstream.Close()
		close(done)
	}()
	io.Copy(conn, upstream)
	conn.Close()
	<-done
}

func renderTunnelSubscription(format, base string, nodes []subscriptionNode) (string, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || !validSubscriptionHost(u.Hostname()) || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", fmt.Errorf("隧道入口必须为 https://域名[:端口]，不含路径")
	}
	port := 443
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return "", fmt.Errorf("隧道端口无效")
		}
	}
	if len(nodes) == 0 {
		return "", fmt.Errorf("请先选择订阅国家并保存")
	}
	var b strings.Builder
	if format != "qx" {
		b.WriteString("# URnetwork WebSocket TLS subscription\nproxies:\n")
	}
	for _, n := range nodes {
		pass, path := tunnelPassword(n.Country), tunnelPath(n.Port)
		if format == "qx" {
			fmt.Fprintf(&b, "trojan=%s, password=%s, obfs=wss, obfs-host=%s, obfs-uri=%s, tls-verification=true, fast-open=false, udp-relay=false, tag=URnetwork-%s\n", net.JoinHostPort(u.Hostname(), strconv.Itoa(port)), pass, u.Hostname(), path, n.Country)
		} else {
			fmt.Fprintf(&b, "  - name: %s\n    type: trojan\n    server: %s\n    port: %d\n    password: %s\n    sni: %s\n    skip-cert-verify: false\n    udp: false\n    network: ws\n    ws-opts:\n      path: %s\n      headers:\n        Host: %s\n", yamlQuote("URnetwork-"+n.Country), yamlQuote(u.Hostname()), port, yamlQuote(pass), yamlQuote(u.Hostname()), yamlQuote(path), yamlQuote(u.Host))
		}
	}
	if format != "qx" {
		b.WriteString("proxy-groups:\n  - name: URnetwork\n    type: select\n    proxies:\n")
		for _, n := range nodes {
			b.WriteString("      - " + yamlQuote("URnetwork-"+n.Country) + "\n")
		}
		b.WriteString("rules:\n  - MATCH,URnetwork\n")
	}
	return b.String(), nil
}
