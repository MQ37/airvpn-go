package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func genKey(t *testing.T) (priv, pub [32]byte) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	copy(priv[:], k.Bytes())
	copy(pub[:], k.PublicKey().Bytes())
	return
}

func b64(k [32]byte) string { return base64.StdEncoding.EncodeToString(k[:]) }

const sampleConf = `# AirVPN
[Interface]
Address = 10.167.1.2/32, fd7d:76ee:3c49:9950:0:3:aa:bb/128
PrivateKey = %s
MTU = 1320
DNS = 10.128.0.1, fd7d:76ee:3c49:9950::1
PostUp = rm -rf /

[Peer]
PublicKey = %s
PresharedKey = %s
Endpoint = %s
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 15
`

func TestParseConfig(t *testing.T) {
	a, _ := genKey(t)
	_, bp := genKey(t)
	psk, _ := genKey(t)
	cfg, err := parseConfig(strings.NewReader(fmt.Sprintf(sampleConf, b64(a), b64(bp), b64(psk), "nl.vpn.airdns.org:1637")))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.privateKey != hex.EncodeToString(a[:]) || cfg.publicKey != hex.EncodeToString(bp[:]) || cfg.presharedKey != hex.EncodeToString(psk[:]) {
		t.Fatal("keys not converted to hex")
	}
	if len(cfg.addresses) != 2 || cfg.addresses[0] != netip.MustParseAddr("10.167.1.2") || len(cfg.dns) != 2 {
		t.Fatalf("addresses/dns: %v %v", cfg.addresses, cfg.dns)
	}
	if cfg.endpoint != "nl.vpn.airdns.org:1637" || cfg.mtu != 1320 || cfg.keepalive != 15 || len(cfg.allowedIPs) != 2 {
		t.Fatalf("got %+v", cfg)
	}
}

func TestParseConfigErrors(t *testing.T) {
	k, _ := genKey(t)
	key := b64(k)
	cases := map[string]string{
		"no peer":    "[Interface]\nPrivateKey=" + key + "\nAddress=10.0.0.2/32\nDNS=10.0.0.1\n",
		"bad key":    "[Interface]\nPrivateKey=abc\n",
		"two peers":  "[Peer]\nPublicKey=" + key + "\n[Peer]\n",
		"no dns":     "[Interface]\nPrivateKey=" + key + "\nAddress=10.0.0.2/32\n[Peer]\nPublicKey=" + key + "\nEndpoint=1.2.3.4:5\n",
		"bad port":   "[Peer]\nEndpoint=1.2.3.4:99999\n",
		"junk line":  "[Interface]\nnonsense\n",
		"bad mtu":    "[Interface]\nMTU=10\n",
		"bad prefix": "[Interface]\nAddress=10.0.0.2\n",
	}
	for name, in := range cases {
		_, err := parseConfig(strings.NewReader(in))
		if err == nil {
			t.Errorf("%s: expected error", name)
		} else if strings.Contains(err.Error(), key) {
			t.Errorf("%s: error leaks the key: %v", name, err)
		}
	}
}

func TestCheckLoopback(t *testing.T) {
	for _, ok := range []string{"127.0.0.1:1080", "[::1]:1080", "localhost:1080"} {
		if err := checkLoopback(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"0.0.0.0:1080", ":1080", "192.168.1.5:1080", "[::]:1080", "example.com:1080"} {
		if err := checkLoopback(bad); err == nil {
			t.Errorf("%s: expected refusal", bad)
		}
	}
}

// socksConnect does a SOCKS5 request and returns the reply code and the conn.
func socksConnect(t *testing.T, proxy string, atyp byte, host string, port int, cmd byte) (byte, net.Conn) {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxy, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(15 * time.Second))
	c.Write([]byte{5, 1, 0})
	var r [2]byte
	if _, err := io.ReadFull(c, r[:]); err != nil || r != [2]byte{5, 0} {
		t.Fatalf("method reply %v %v", r, err)
	}
	req := []byte{5, cmd, 0, atyp}
	switch atyp {
	case 1:
		req = append(req, netip.MustParseAddr(host).AsSlice()...)
	case 3:
		req = append(req, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))
	c.Write(req)
	var rep [10]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		t.Fatal(err)
	}
	return rep[1], c
}

func startSOCKS(t *testing.T, dial dialFunc) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go serveSOCKS(l, dial, t.Logf)
	t.Cleanup(func() { l.Close() })
	return l.Addr().String()
}

func echoServer(l net.Listener) {
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
}

func TestSOCKSAgainstPlainDialer(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	echoServer(l)
	var d net.Dialer
	proxy := startSOCKS(t, d.DialContext)
	port := l.Addr().(*net.TCPAddr).Port

	code, c := socksConnect(t, proxy, 1, "127.0.0.1", port, 1)
	if code != 0 {
		t.Fatalf("connect reply %d", code)
	}
	c.Write([]byte("ping"))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo %q %v", buf, err)
	}
	c.Close()

	// A name goes to the dialer untouched (atyp 3), so DNS happens where the dialer decides.
	var got string
	proxy2 := startSOCKS(t, func(ctx context.Context, n, a string) (net.Conn, error) {
		got = a
		return nil, fmt.Errorf("nope")
	})
	code, c = socksConnect(t, proxy2, 3, "example.test", 443, 1)
	c.Close()
	if code != repFail || got != "example.test:443" {
		t.Fatalf("code %d target %q", code, got)
	}

	code, c = socksConnect(t, proxy, 1, "127.0.0.1", port, 3) // UDP ASSOCIATE
	c.Close()
	if code != repCmdUnsupported {
		t.Fatalf("udp associate reply %d", code)
	}
	l2, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := l2.Addr().(*net.TCPAddr).Port
	l2.Close()
	code, c = socksConnect(t, proxy, 1, "127.0.0.1", closed, 1)
	c.Close()
	if code != repRefused {
		t.Fatalf("refused reply %d", code)
	}
}

// fakeAirVPN is an API server that implements the same envelope as AirVPN: it
// unwraps s with its RSA key, decrypts d, and answers with encrypted XML.
type fakeAirVPN struct {
	key      *rsa.PrivateKey
	login    string
	password string
	answers  map[string]string // act -> XML
	gotActs  []string
}

func (f *fakeAirVPN) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	s, _ := base64.StdEncoding.DecodeString(r.PostForm.Get("s"))
	d, _ := base64.StdEncoding.DecodeString(r.PostForm.Get("d"))
	sPlain, err := rsa.DecryptPKCS1v15(rand.Reader, f.key, s)
	if err != nil {
		http.Error(w, "bad s", 400)
		return
	}
	sp := decodeAssoc(sPlain)
	blk, _ := aes.NewCipher(sp["key"])
	plain := make([]byte, len(d))
	cipher.NewCBCDecrypter(blk, sp["iv"]).CryptBlocks(plain, d)
	plain, err = pkcs7Unpad(plain)
	if err != nil {
		http.Error(w, "bad d", 400)
		return
	}
	p := decodeAssoc(plain)
	f.gotActs = append(f.gotActs, string(p["act"]))
	xmlOut, ok := f.answers[string(p["act"])]
	if string(p["login"]) != f.login || string(p["password"]) != f.password {
		xmlOut, ok = `<user message="Authentication failed"/>`, true
	}
	if !ok {
		xmlOut = `<error error="unknown act"/>`
	}
	out := pkcs7Pad([]byte(xmlOut))
	enc := make([]byte, len(out))
	cipher.NewCBCEncrypter(blk, sp["iv"]).CryptBlocks(enc, out)
	w.Write(enc)
}

func decodeAssoc(b []byte) map[string][]byte {
	m := map[string][]byte{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		k, v, _ := strings.Cut(line, ":")
		kb, _ := base64.StdEncoding.DecodeString(k)
		vb, _ := base64.StdEncoding.DecodeString(v)
		m[string(kb)] = vb
	}
	return m
}

func newFake(t *testing.T, answers map[string]string) (*fakeAirVPN, *apiClient) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeAirVPN{key: k, login: "alice", password: "s3cret pass", answers: answers}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c, err := newAPIClient(f.login, f.password)
	if err != nil {
		t.Fatal(err)
	}
	c.pub = &k.PublicKey
	c.bootstrap = []string{"http://127.0.0.1:1", srv.URL} // first endpoint is dead: must fail over
	return f, c
}

func manifestXML(endpoint string) string {
	return fmt.Sprintf(`<manifest>
<servers_groups><servers_group group="g1" country_code="nl" location="Alblasserdam" support_ipv4="true" users_max="100" bw_max="1000"/></servers_groups>
<servers>
 <server name="Busy" group="g1" ips_entry="%s" users="90" bw="900"/>
 <server name="Alpha" group="g1" ips_entry="%s,%s" users="10" bw="100"/>
 <server name="Shut" group="g1" ips_entry="10.0.0.9" users="0" bw="0" warning_closed="maintenance"/>
</servers>
<modes><mode type="openvpn" protocol="udp" port="443"/><mode type="wireguard" protocol="udp" port="1637" entry_index="0"/><mode type="wireguard" protocol="udp" port="47107" entry_index="1"/></modes>
</manifest>`, endpoint, endpoint, "10.0.0.2")
}

func userXML(priv, serverPub, psk [32]byte) string {
	return fmt.Sprintf(`<user login="alice" wg_public_key="%s"><keys>
<key name="Default" wg_private_key="%s" wg_ipv4="10.9.0.2/32" wg_ipv6="fd00::2/128" wg_dns_ipv4="10.9.0.1" wg_dns_ipv6="fd00::1" wg_preshared="%s"/>
<key name="Other" wg_private_key="%s" wg_ipv4="10.9.0.3/32" wg_dns_ipv4="10.9.0.1" wg_preshared="%s"/>
</keys></user>`, b64(serverPub), b64(priv), b64(psk), b64(priv), b64(psk))
}

func TestAPILoginServersAndConfig(t *testing.T) {
	cPriv, _ := genKey(t)
	_, sPub := genKey(t)
	psk, _ := genKey(t)
	f, c := newFake(t, map[string]string{"user": userXML(cPriv, sPub, psk), "manifest": manifestXML("203.0.113.7")})
	ctx := context.Background()

	user, err := c.fetch(ctx, "user")
	if err != nil {
		t.Fatal(err)
	}
	m, err := c.fetch(ctx, "manifest")
	if err != nil {
		t.Fatal(err)
	}
	all := listServers(m)
	if len(all) != 3 || all[0].Name != "Alpha" || all[0].Country != "nl" || all[0].Users != 10 {
		t.Fatalf("servers: %+v", all)
	}
	best, err := pickServer(all, "")
	if err != nil || best.Name != "Alpha" { // least loaded, open
		t.Fatalf("best %+v %v", best, err)
	}
	if _, err := pickServer(all, "shut"); err == nil {
		t.Fatal("closed server must be refused")
	}
	if _, err := pickServer(all, "nope"); err == nil {
		t.Fatal("unknown server must error")
	}
	srv, _ := pickServer(all, "alpha") // case-insensitive
	cfg, err := buildConfig(user, m, srv, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.endpoint != "203.0.113.7:1637" || cfg.privateKey != hex.EncodeToString(cPriv[:]) ||
		cfg.publicKey != hex.EncodeToString(sPub[:]) || cfg.presharedKey != hex.EncodeToString(psk[:]) {
		t.Fatalf("config %+v", cfg)
	}
	if len(cfg.addresses) != 2 || len(cfg.dns) != 2 {
		t.Fatalf("addr/dns %v %v", cfg.addresses, cfg.dns)
	}
	if cfg2, err := buildConfig(user, m, srv, "Other", 47107); err != nil || cfg2.endpoint != "10.0.0.2:47107" || len(cfg2.addresses) != 1 {
		t.Fatalf("second key/port: %+v %v", cfg2, err)
	}
	if _, err := buildConfig(user, m, srv, "Missing", 0); err == nil {
		t.Fatal("unknown key name must error")
	}
	if len(f.gotActs) != 2 || f.gotActs[0] != "user" || f.gotActs[1] != "manifest" {
		t.Fatalf("acts %v", f.gotActs)
	}
}

func TestAPIWrongPassword(t *testing.T) {
	f, c := newFake(t, map[string]string{"user": "<user/>"})
	_ = f
	c.password = "wrong"
	_, err := c.fetch(context.Background(), "user")
	if err == nil || !strings.Contains(err.Error(), "Authentication failed") {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), "wrong") && !strings.Contains(err.Error(), "Authentication failed") {
		t.Fatal("password leaked")
	}
}

// TestEndToEnd covers the whole chain: login against a fake AirVPN API, key and
// server selection, a real WireGuard handshake against an in-process peer, and
// a TCP echo reached through the SOCKS port.
func TestEndToEnd(t *testing.T) {
	cPriv, cPub := genKey(t)
	sPriv, sPub := genKey(t)
	psk, _ := genKey(t)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sPort := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()

	srvAddr := netip.MustParseAddr("10.9.0.1")
	stun, snet, err := netstack.CreateNetTUN([]netip.Addr{srvAddr}, []netip.Addr{srvAddr}, 1320)
	if err != nil {
		t.Fatal(err)
	}
	sdev := device.NewDevice(stun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "srv: "))
	defer sdev.Close()
	err = sdev.IpcSet(fmt.Sprintf("private_key=%x\nlisten_port=%d\npublic_key=%x\npreshared_key=%x\nallowed_ip=10.9.0.2/32\n",
		sPriv, sPort, cPub, psk))
	if err != nil {
		t.Fatal(err)
	}
	if err := sdev.Up(); err != nil {
		t.Fatal(err)
	}
	el, err := snet.ListenTCP(&net.TCPAddr{Port: 7})
	if err != nil {
		t.Fatal(err)
	}
	defer el.Close()
	echoServer(el)

	manifest := strings.NewReplacer(`port="1637"`, fmt.Sprintf(`port="%d"`, sPort)).Replace(manifestXML("127.0.0.1"))
	_, c := newFake(t, map[string]string{"user": userXML(cPriv, sPub, psk), "manifest": manifest})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	user, err := c.fetch(ctx, "user")
	if err != nil {
		t.Fatal(err)
	}
	m, err := c.fetch(ctx, "manifest")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := pickServer(listServers(m), "")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := buildConfig(user, m, srv, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	tn, err := startTunnel(ctx, cfg, device.LogLevelError)
	if err != nil {
		t.Fatal(err)
	}
	defer tn.Close()

	proxy := startSOCKS(t, tn.DialContext)
	code, sc := socksConnect(t, proxy, 1, "10.9.0.1", 7, 1)
	if code != 0 {
		t.Fatalf("connect through tunnel: reply %d", code)
	}
	defer sc.Close()
	msg := strings.Repeat("through-wireguard ", 1000)
	go sc.Write([]byte(msg))
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(sc, buf); err != nil || string(buf) != msg {
		t.Fatalf("echo through tunnel failed: %v", err)
	}
	if tn.lastHandshake().IsZero() {
		t.Fatal("no handshake recorded")
	}
	// The tunnel is the only way out: a host-local service must not be reachable.
	hl, _ := net.Listen("tcp", "127.0.0.1:0")
	defer hl.Close()
	echoServer(hl)
	code, c2 := socksConnect(t, proxy, 1, "127.0.0.1", hl.Addr().(*net.TCPAddr).Port, 1)
	c2.Close()
	if code == 0 {
		t.Fatal("proxy reached the host network instead of the tunnel")
	}
}
