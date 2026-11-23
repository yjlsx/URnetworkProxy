package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

const maxSubscriptionCountries = 8

type subscriptionNode struct {
	Country string `json:"country"`
	Port    int    `json:"port"`
}

type subscriptionManager struct {
	mu      sync.Mutex
	opMu    sync.Mutex
	nodes   []subscriptionNode
	workers map[string]*Server
	closed  bool
}

var subscriptions = &subscriptionManager{workers: make(map[string]*Server)}

// Export a snapshot of running workers, not merely the checked/saved countries.
func (s *Server) handleSubscriptionLinks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	nodes := subscriptions.snapshot()
	var running []subscriptionNode
	subscriptions.mu.Lock()
	for _, n := range nodes {
		if worker := subscriptions.workers[n.Country]; worker != nil {
			worker.mu.Lock()
			active := worker.running && !worker.busy && !worker.retired
			worker.mu.Unlock()
			if active {
				running = append(running, n)
			}
		}
	}
	subscriptions.mu.Unlock()
	links := make([]map[string]string, 0, len(running))
	for _, n := range running {
		var uri, qx string
		var err error
		if r.URL.Query().Get("transport") == "wss" {
			base := r.URL.Query().Get("base")
			qx, err = renderTunnelSubscription("qx", base, []subscriptionNode{n})
			if err == nil {
				u, _ := url.Parse(base)
				port := u.Port()
				if port == "" {
					port = "443"
				}
				query := url.Values{"security": {"tls"}, "type": {"ws"}, "sni": {u.Hostname()}, "host": {u.Hostname()}, "path": {tunnelPath(n.Port)}}
				uri = (&url.URL{Scheme: "trojan", User: url.User(tunnelPassword(n.Country)), Host: net.JoinHostPort(u.Hostname(), port), RawQuery: query.Encode(), Fragment: "URnetwork-" + n.Country}).String()
			}
		} else {
			host := nodeHostFrom(r.URL.Query().Get("host"))
			qx, err = renderSubscription("qx", host, []subscriptionNode{n}, socksUser, socksPassword())
			if err == nil {
				uri = (&url.URL{Scheme: "socks5", User: url.UserPassword(socksUser, socksPassword()), Host: net.JoinHostPort(host, strconv.Itoa(n.Port)), Fragment: "URnetwork-" + n.Country}).String()
			}
		}
		if err != nil {
			http.Error(w, "无法生成节点链接："+err.Error(), http.StatusBadRequest)
			return
		}
		links = append(links, map[string]string{"country": n.Country, "uri": uri, "qx": strings.TrimSpace(qx)})
	}
	json.NewEncoder(w).Encode(map[string]any{"nodes": links})
}

func subscriptionFile() string { return filepath.Join(filepath.Dir(confFile), "subscriptions.json") }

func validateNodes(nodes []subscriptionNode) error {
	if len(nodes) > maxSubscriptionCountries {
		return fmt.Errorf("最多选择 %d 个国家", maxSubscriptionCountries)
	}
	countries, ports := map[string]bool{}, map[int]bool{}
	for _, n := range nodes {
		if n.Country == "" || strings.ContainsAny(n.Country, ",\r\n=") || len(n.Country) > 100 || countries[n.Country] {
			return fmt.Errorf("国家名称为空、重复或包含不支持的字符")
		}
		_, panelPort, _ := net.SplitHostPort(listenAddr)
		if n.Port < 1024 || n.Port > 65535 || n.Port == proxyPort || strconv.Itoa(n.Port) == panelPort || ports[n.Port] {
			return fmt.Errorf("订阅端口必须在 1024–65535 内，且不能重复或占用主代理、面板端口")
		}
		countries[n.Country], ports[n.Port] = true, true
	}
	return nil
}

// Keep an existing country's port when countries are reordered or added.
func allocateNodes(countries []string, old []subscriptionNode) ([]subscriptionNode, error) {
	nodes := make([]subscriptionNode, 0, len(countries))
	used := map[int]bool{proxyPort: true}
	_, panelPort, _ := net.SplitHostPort(listenAddr)
	p, _ := strconv.Atoi(panelPort)
	used[p] = true
	for _, c := range countries {
		n := subscriptionNode{Country: c}
		for _, existing := range old {
			if existing.Country == c {
				n.Port = existing.Port
				used[n.Port] = true
				break
			}
		}
		nodes = append(nodes, n)
	}
	for i := range nodes {
		if nodes[i].Port != 0 {
			continue
		}
		for p := 10000; p <= 65535; p++ {
			if !used[p] {
				nodes[i].Port = p
				used[p] = true
				break
			}
		}
	}
	return nodes, validateNodes(nodes)
}

func (m *subscriptionManager) load() error {
	b, err := os.ReadFile(subscriptionFile())
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var nodes []subscriptionNode
	if err := json.Unmarshal(b, &nodes); err != nil {
		return err
	}
	if err := validateNodes(nodes); err != nil {
		return err
	}
	m.mu.Lock()
	m.nodes = nodes
	m.mu.Unlock()
	return nil
}

func (m *subscriptionManager) snapshot() []subscriptionNode {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]subscriptionNode{}, m.nodes...)
}

func (m *subscriptionManager) configure(countries []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	nodes, err := allocateNodes(countries, m.nodes)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(nodes, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(subscriptionFile()), 0700); err != nil {
		return err
	}
	tmp := subscriptionFile() + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, subscriptionFile()); err != nil {
		return err
	}
	m.nodes = nodes
	return nil
}

func retireWorker(w *Server) {
	w.opMu.Lock()
	defer w.opMu.Unlock()
	w.mu.Lock()
	w.retired = true
	w.mu.Unlock()
	w.stopLocked()
}

func (m *subscriptionManager) reconcile(restart bool) {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	if m.closed {
		return
	}
	nodes := m.snapshot()
	wanted := make(map[string]int)
	for _, n := range nodes {
		wanted[n.Country] = n.Port
	}
	m.mu.Lock()
	var retired []*Server
	for c, w := range m.workers {
		if restart || wanted[c] != w.port {
			retired = append(retired, w)
			delete(m.workers, c)
		}
	}
	m.mu.Unlock()
	for _, w := range retired {
		retireWorker(w)
	}
	// Start sequentially to avoid an authentication burst against the upstream API.
	for _, n := range nodes {
		m.mu.Lock()
		w := m.workers[n.Country]
		fresh := w == nil
		if fresh {
			w = NewServer()
			w.port = n.Port
			w.isolated = true
			m.workers[n.Country] = w
		}
		m.mu.Unlock()
		w.mu.Lock()
		running := w.running
		w.mu.Unlock()
		if fresh || !running {
			w.Switch(n.Country)
		}
	}
}

func (m *subscriptionManager) stopAll() {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	m.closed = true
	m.mu.Lock()
	workers := m.workers
	m.workers = make(map[string]*Server)
	m.mu.Unlock()
	for _, w := range workers {
		retireWorker(w)
	}
}

func validSubscriptionHost(host string) bool {
	return net.ParseIP(host) != nil || isHostname(host)
}

func renderSubscription(format, host string, nodes []subscriptionNode, user, pass string) (string, error) {
	if !validSubscriptionHost(host) {
		return "", fmt.Errorf("节点地址无效")
	}
	if len(nodes) == 0 {
		return "", fmt.Errorf("请先选择订阅国家并保存")
	}
	var b strings.Builder
	if format == "qx" {
		if strings.ContainsAny(user+pass, ",\r\n") || strings.TrimSpace(user) != user || strings.TrimSpace(pass) != pass {
			return "", fmt.Errorf("Quantumult X 不支持当前凭据中的分隔符或首尾空格，请更换 SOCKS5 凭据")
		}
		for _, n := range nodes {
			if strings.ContainsAny(n.Country, ",\r\n=") {
				return "", fmt.Errorf("国家名称包含不支持的字符")
			}
			fmt.Fprintf(&b, "socks5=%s, username=%s, password=%s, udp-relay=false, tag=URnetwork-%s\n", net.JoinHostPort(host, strconv.Itoa(n.Port)), user, pass, n.Country)
		}
		return b.String(), nil
	}
	b.WriteString("# URnetwork 多国家订阅\ndns:\n  proxy-server-nameserver: [223.5.5.5, 1.1.1.1]\nproxies:\n")
	for _, n := range nodes {
		fmt.Fprintf(&b, "  - name: %s\n    type: socks5\n    server: %s\n    port: %d\n    username: %s\n    password: %s\n    udp: false\n", yamlQuote("URnetwork-"+n.Country), yamlQuote(host), n.Port, yamlQuote(user), yamlQuote(pass))
	}
	b.WriteString("proxy-groups:\n  - name: URnetwork\n    type: select\n    proxies:\n")
	for _, n := range nodes {
		b.WriteString("      - " + yamlQuote("URnetwork-"+n.Country) + "\n")
	}
	b.WriteString("rules:\n  - MATCH,URnetwork\n")
	return b.String(), nil
}

func (s *Server) handleSubscriptions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fail := func(status int, err error) {
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
	}
	if r.Method == "POST" {
		var body struct {
			Countries []string `json:"countries"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&body); err != nil {
			fail(400, err)
			return
		}
		if len(body.Countries) > maxSubscriptionCountries {
			fail(400, fmt.Errorf("最多选择 %d 个国家", maxSubscriptionCountries))
			return
		}
		// Known saved countries remain removable/editable when the upstream directory is offline.
		known := map[string]bool{}
		for _, n := range subscriptions.snapshot() {
			known[n.Country] = true
		}
		if len(body.Countries) > 0 {
			regions, err := s.loadRegions(false)
			for _, region := range regions {
				known[region.Name] = true
			}
			for _, country := range body.Countries {
				if !known[country] {
					if err != nil {
						fail(502, err)
					} else {
						fail(400, fmt.Errorf("未知国家: %s", country))
					}
					return
				}
			}
		}
		if err := subscriptions.configure(body.Countries); err != nil {
			fail(400, err)
			return
		}
		go subscriptions.reconcile(false)
	} else if r.Method != "GET" {
		w.WriteHeader(405)
		return
	}
	nodes := subscriptions.snapshot()
	states := make([]map[string]any, 0, len(nodes))
	subscriptions.mu.Lock()
	for _, n := range nodes {
		state := map[string]any{"country": n.Country, "port": n.Port, "running": false, "busy": false, "error": "", "probeError": "", "exitIP": "", "latencyMs": int64(0), "exitHistory": []exitObservation{}}
		if worker := subscriptions.workers[n.Country]; worker != nil {
			worker.mu.Lock()
			state["running"] = worker.running
			state["busy"] = worker.busy
			state["error"] = worker.lastErr
			state["exitIP"] = worker.exitIP
			state["probeError"] = worker.probeErr
			state["latencyMs"] = worker.latency
			state["exitHistory"] = append([]exitObservation(nil), worker.exitHistory...)
			worker.mu.Unlock()
		}
		states = append(states, state)
	}
	subscriptions.mu.Unlock()
	json.NewEncoder(w).Encode(map[string]any{"nodes": states, "nodeHost": nodeHostFrom(""), "bindHost": env("URNET_BIND_HOST", "0.0.0.0"), "maxCountries": maxSubscriptionCountries, "clashPath": "/sub/" + subToken() + ".yaml", "qxPath": "/sub/" + subToken() + ".conf"})
}
