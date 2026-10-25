package app

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// apiClient speaks AirVPN's account API the way Eddie does: every request is a
// form POST with two fields. "s" is a fresh AES-256 key+IV wrapped with
// AirVPN's RSA public key, "d" is the parameters encrypted with that AES key
// (CBC, PKCS#7). The answer is XML encrypted with the same key and IV.
type apiClient struct {
	login, password string
	pub             *rsa.PublicKey
	bootstrap       []string
	http            *http.Client
}

func newAPIClient(login, password string) (*apiClient, error) {
	mod, err := base64.StdEncoding.DecodeString(airvpnRSAModulus)
	if err != nil {
		return nil, err
	}
	exp, err := base64.StdEncoding.DecodeString(airvpnRSAExponent)
	if err != nil {
		return nil, err
	}
	return &apiClient{
		login:     login,
		password:  password,
		pub:       &rsa.PublicKey{N: new(big.Int).SetBytes(mod), E: int(new(big.Int).SetBytes(exp).Int64())},
		bootstrap: airvpnBootstrap,
		http:      &http.Client{Timeout: 20 * time.Second},
	}, nil
}

// assoc encodes parameters as Eddie does: base64(key):base64(value) per line.
func assoc(keys []string, vals map[string][]byte) []byte {
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(base64.StdEncoding.EncodeToString([]byte(k)))
		b.WriteByte(':')
		b.WriteString(base64.StdEncoding.EncodeToString(vals[k]))
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

func pkcs7Pad(p []byte) []byte {
	n := aes.BlockSize - len(p)%aes.BlockSize
	return append(p, bytes.Repeat([]byte{byte(n)}, n)...)
}

func pkcs7Unpad(p []byte) ([]byte, error) {
	if len(p) == 0 || len(p)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("bad ciphertext length %d", len(p))
	}
	n := int(p[len(p)-1])
	if n == 0 || n > aes.BlockSize || n > len(p) {
		return nil, fmt.Errorf("bad padding")
	}
	return p[:len(p)-n], nil
}

// seal builds the s and d form values and returns the AES key material needed
// to read the answer.
func (c *apiClient) seal(params map[string]string) (s, d string, blk cipher.Block, iv []byte, err error) {
	key, iv := make([]byte, 32), make([]byte, aes.BlockSize)
	if _, err = io.ReadFull(rand.Reader, key); err != nil {
		return
	}
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}
	wrapped, err := rsa.EncryptPKCS1v15(rand.Reader, c.pub,
		assoc([]string{"key", "iv"}, map[string][]byte{"key": key, "iv": iv}))
	if err != nil {
		return
	}
	if blk, err = aes.NewCipher(key); err != nil {
		return
	}
	names := make([]string, 0, len(params))
	vals := map[string][]byte{}
	for k, v := range params {
		names = append(names, k)
		vals[k] = []byte(v)
	}
	sort.Strings(names)
	plain := pkcs7Pad(assoc(names, vals))
	enc := make([]byte, len(plain))
	cipher.NewCBCEncrypter(blk, iv).CryptBlocks(enc, plain)
	return base64.StdEncoding.EncodeToString(wrapped), base64.StdEncoding.EncodeToString(enc), blk, iv, nil
}

func openAnswer(body []byte, blk cipher.Block, iv []byte) ([]byte, error) {
	if len(body)%aes.BlockSize != 0 { // tolerate a base64 wrapped answer
		if raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body))); err == nil {
			body = raw
		}
	}
	if len(body) == 0 || len(body)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("unexpected answer (%d bytes)", len(body))
	}
	plain := make([]byte, len(body))
	cipher.NewCBCDecrypter(blk, iv).CryptBlocks(plain, body)
	return pkcs7Unpad(plain)
}

// node reads the attributes of any XML element.
type node struct {
	Attrs []xml.Attr `xml:",any,attr"`
}

func (n node) get(name string) string {
	for _, a := range n.Attrs {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

// document is the union of the "user" and "manifest" answers; the root
// element's own name is not interesting.
type document struct {
	node
	Keys    []node `xml:"keys>key"`
	Servers []node `xml:"servers>server"`
	Groups  []node `xml:"servers_groups>servers_group"`
	Modes   []node `xml:"modes>mode"`
}

// fetch tries every bootstrap endpoint in turn and returns the first valid
// answer. A server-side message or error (wrong password, ...) stops at once.
func (c *apiClient) fetch(ctx context.Context, act string) (*document, error) {
	var firstErr error
	for _, base := range c.bootstrap {
		doc, err := c.fetchFrom(ctx, base, act)
		if err == nil {
			return doc, nil
		}
		if _, fatal := err.(serverError); fatal {
			return nil, err
		}
		if firstErr == nil {
			firstErr = err
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, firstErr
}

type serverError string

func (e serverError) Error() string { return "AirVPN: " + string(e) }

func (c *apiClient) fetchFrom(ctx context.Context, base, act string) (*document, error) {
	s, d, blk, iv, err := c.seal(map[string]string{
		"act": act, "login": c.login, "password": c.password,
		"software": "airvpn-go", "arch": "x64", "system": "linux_x64", "version": "2300",
	})
	if err != nil {
		return nil, err
	}
	form := url.Values{"s": {s}, "d": {d}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", base, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", base, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", base, err)
	}
	plain, err := openAnswer(body, blk, iv)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", base, err)
	}
	var doc document
	if err := xml.Unmarshal(plain, &doc); err != nil {
		return nil, fmt.Errorf("%s: bad XML answer: %w", base, err)
	}
	if m := doc.get("error"); m != "" {
		return nil, serverError(m)
	}
	if m := doc.get("message"); m != "" && act == "user" {
		return nil, serverError(m)
	}
	return &doc, nil
}

// server is one entry of the manifest with group defaults applied.
type server struct {
	Name, Country, Location string
	Entries                 []netip.Addr
	Users, UsersMax         int
	BW, BWMax               int64
	closed                  bool
	IPv4                    bool
}

func (s server) load() float64 {
	u, b := float64(s.Users)/maxf(float64(s.UsersMax), 1), float64(s.BW)/maxf(float64(s.BWMax), 1)
	return maxf(u, b)
}

func maxf(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func listServers(m *document) []server {
	groups := map[string]node{}
	for _, g := range m.Groups {
		groups[g.get("group")] = g
	}
	var out []server
	for _, n := range m.Servers {
		attr := func(k string) string { // server value, else its group's
			if v := n.get(k); v != "" {
				return v
			}
			return groups[n.get("group")].get(k)
		}
		s := server{Name: n.get("name"), Country: attr("country_code"), Location: attr("location"),
			closed: attr("warning_closed") != "", IPv4: attr("support_ipv4") == "true" || attr("support_ipv4") == "1"}
		s.Users, _ = strconv.Atoi(attr("users"))
		s.UsersMax, _ = strconv.Atoi(attr("users_max"))
		s.BW, _ = strconv.ParseInt(attr("bw"), 10, 64)
		s.BWMax, _ = strconv.ParseInt(attr("bw_max"), 10, 64)
		for _, f := range strings.Split(attr("ips_entry"), ",") {
			if a, err := netip.ParseAddr(strings.TrimSpace(f)); err == nil {
				s.Entries = append(s.Entries, a)
			}
		}
		if s.Name != "" && len(s.Entries) > 0 {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// buildConfig turns the account's key and the chosen server into the same
// wgConfig that a Config Generator file would give.
func buildConfig(user, manifest *document, srv server, keyName string, port int) (*wgConfig, error) {
	var key *node
	for i, k := range user.Keys {
		if keyName == "" || k.get("name") == keyName {
			key = &user.Keys[i]
			break
		}
	}
	if key == nil {
		return nil, fmt.Errorf("no device key named %q on the account (create one in the AirVPN Client Area)", keyName)
	}
	cfg := &wgConfig{mtu: 1320, keepalive: 15, allowedIPs: []string{"0.0.0.0/0", "::/0"}}
	var err error
	if cfg.privateKey, err = hexKey(key.get("wg_private_key")); err != nil {
		return nil, fmt.Errorf("device key %q has no WireGuard private key", key.get("name"))
	}
	if cfg.publicKey, err = hexKey(user.get("wg_public_key")); err != nil {
		return nil, fmt.Errorf("account answer has no WireGuard server public key")
	}
	if v := key.get("wg_preshared"); v != "" {
		if cfg.presharedKey, err = hexKey(v); err != nil {
			return nil, fmt.Errorf("bad preshared key")
		}
	}
	for _, a := range []string{"wg_ipv4", "wg_ipv6"} {
		if v := key.get(a); v != "" {
			p, err := netip.ParsePrefix(v)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", a, err)
			}
			cfg.addresses = append(cfg.addresses, p.Addr())
		}
	}
	for _, a := range []string{"wg_dns_ipv4", "wg_dns_ipv6"} {
		if v := key.get(a); v != "" {
			ip, err := netip.ParseAddr(v)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", a, err)
			}
			cfg.dns = append(cfg.dns, ip)
		}
	}
	if len(cfg.addresses) == 0 || len(cfg.dns) == 0 {
		return nil, fmt.Errorf("device key %q lacks WireGuard addresses or DNS", key.get("name"))
	}
	// Pick the WireGuard mode (first one, or the one on the requested port); its
	// entry_index chooses which of the server's entry IPs to use.
	var mode node
	for _, m := range manifest.Modes {
		if !strings.EqualFold(m.get("type"), "wireguard") {
			continue
		}
		if p, _ := strconv.Atoi(m.get("port")); port == 0 || p == port {
			mode = m
			break
		}
	}
	if port == 0 {
		if port, _ = strconv.Atoi(mode.get("port")); port == 0 {
			port = 1637
		}
	}
	var v4 []netip.Addr
	for _, e := range srv.Entries {
		if e.Is4() {
			v4 = append(v4, e)
		}
	}
	entry := srv.Entries[0]
	if len(v4) > 0 {
		entry = v4[0]
		if i, _ := strconv.Atoi(mode.get("entry_index")); i > 0 && i < len(v4) {
			entry = v4[i]
		}
	}
	cfg.endpoint = netip.AddrPortFrom(entry, uint16(port)).String()
	return cfg, nil
}
