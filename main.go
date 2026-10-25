// airvpn-go logs in to an AirVPN account (or reads a WireGuard config) and
// serves a local SOCKS5 proxy. The tunnel runs in userspace inside this
// process: no root, no TUN device, no system routes. Only programs that use the
// proxy go through the VPN.
//
// Two ways to drive it: flags and environment (scripts, agents: never prompts
// when stdin is not a terminal or with -no-input, -json for machine output) and
// an interactive menu (a human on a terminal, no arguments).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

const usage = `airvpn-go: a local SOCKS5 proxy through your AirVPN account (userspace WireGuard, no root)

Humans:   airvpn-go            (no arguments, on a terminal: interactive menu)
Scripts:  airvpn-go <command> [flags]

Commands:
  menu        interactive menu: pick a country and server, then run the proxy
  countries   list countries with server counts and load
  servers     list servers (-country cc to filter)
  socks       log in and serve the SOCKS5 proxy (blocks until stopped)
  forget      delete the saved credentials
  help        this text; every command also takes -h

Credentials (on a terminal you are simply asked):
  login       -login NAME or AIRVPN_LOGIN
  password    AIRVPN_PASSWORD or -password-file FILE (never a flag)
  saved       after a successful typed login you are asked "Save? [y/N]" (default no).
              Saved credentials are used automatically, also without a terminal. They
              are stored unencrypted, owner-only (0600), in ~/.config/airvpn-go/.

Examples:
  airvpn-go countries -json
  airvpn-go socks -country nl                  best open server in the Netherlands
  airvpn-go socks -s Alpha -l 127.0.0.1:9050   a named server, another port
  airvpn-go socks -country de -check           log in, handshake, report, exit
  airvpn-go socks -c airvpn.conf               a Config Generator file, no login

For agents: stdout carries data only (tables, or JSON with -json), stderr carries
logs and errors. With -json, "socks" prints one {"event":"ready",...} line on
stdout once the tunnel is up and the port is listening. Exit codes: 0 success,
1 failure (with -json the error is {"error":"..."} on stderr), 2 usage.
Prompts are never shown when stdin is not a terminal or with -no-input.
`

var (
	jsonOut bool
	noInput bool
)

func main() {
	if len(os.Args) < 2 {
		if isTerminal(os.Stdin) {
			exit(cmdMenu(nil))
		}
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch args := os.Args[2:]; os.Args[1] {
	case "menu":
		err = cmdMenu(args)
	case "countries":
		err = cmdCountries(args)
	case "servers":
		err = cmdServers(args)
	case "socks":
		err = cmdSocks(args)
	case "forget":
		err = cmdForget(args)
	case "help", "-h", "-help", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "airvpn-go: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	exit(err)
}

func exit(err error) {
	if err == nil || errors.Is(err, errQuit) {
		os.Exit(0)
	}
	if jsonOut {
		b, _ := json.Marshal(map[string]string{"error": err.Error()})
		fmt.Fprintln(os.Stderr, string(b))
	} else {
		fmt.Fprintln(os.Stderr, "airvpn-go:", err)
	}
	os.Exit(1)
}

// commonFlags are accepted by every command that talks to AirVPN.
type commonFlags struct {
	login, pwFile string
}

func newFlagSet(name, summary string, c *commonFlags) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "airvpn-go %s: %s\n\nflags:\n", name, summary)
		fs.PrintDefaults()
	}
	if c != nil {
		fs.StringVar(&c.login, "login", "", "AirVPN account login (or AIRVPN_LOGIN)")
		fs.StringVar(&c.pwFile, "password-file", "", "file holding the account password (or AIRVPN_PASSWORD)")
	}
	fs.BoolVar(&jsonOut, "json", false, "machine-readable output (JSON)")
	fs.BoolVar(&noInput, "no-input", false, "never prompt, fail instead")
	return fs
}

func parseFlags(fs *flag.FlagSet, args []string) error {
	fs.Parse(args)
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q (see -h)", fs.Arg(0))
	}
	return nil
}

// account logs in and downloads the server list.
func account(ctx context.Context, c commonFlags) (user, manifest *document, err error) {
	cr, err := credentials(c.login, c.pwFile)
	if err != nil {
		return nil, nil, err
	}
	api, err := newAPIClient(cr.login, cr.password)
	if err != nil {
		return nil, nil, err
	}
	fmt.Fprintln(os.Stderr, "logging in to AirVPN ...")
	if user, err = api.fetch(ctx, "user"); err != nil {
		if cr.fromSaved {
			err = fmt.Errorf("%w (these were the saved credentials: run \"airvpn-go forget\" to delete them)", err)
		}
		return nil, nil, err
	}
	if manifest, err = api.fetch(ctx, "manifest"); err != nil {
		return nil, nil, err
	}
	// Only after a login that worked, so a typo is never saved.
	offerSave(cr, !noInput && !jsonOut && isTerminal(os.Stdin),
		func() (string, error) { return readLine(os.Stdin) }, os.Stderr)
	return user, manifest, nil
}

func cmdForget(args []string) error {
	fs := newFlagSet("forget", "delete the saved credentials", nil)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	p := shownPath()
	ok, err := forgetCreds()
	switch {
	case err != nil:
		return err
	case ok:
		fmt.Fprintf(os.Stderr, "deleted saved credentials (%s)\n", p)
	default:
		fmt.Fprintln(os.Stderr, "no saved credentials")
	}
	return nil
}

func notifyCtx() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func printJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Println(string(b))
	return err
}

func pct(f float64) int { return int(100*f + 0.5) }

func cmdCountries(args []string) error {
	var c commonFlags
	fs := newFlagSet("countries", "list countries with server counts and load", &c)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	ctx, stop := notifyCtx()
	defer stop()
	_, manifest, err := account(ctx, c)
	if err != nil {
		return err
	}
	list := listCountries(listServers(manifest))
	if jsonOut {
		type row struct {
			Code        string `json:"code"`
			Name        string `json:"name"`
			Servers     int    `json:"servers"`
			Open        int    `json:"open"`
			LoadPercent int    `json:"load_percent"`
			Users       int    `json:"users"`
		}
		rows := make([]row, 0, len(list))
		for _, x := range list {
			rows = append(rows, row{x.Code, x.Name, x.Servers, x.Open, pct(x.Load), x.Users})
		}
		return printJSON(rows)
	}
	fmt.Printf("%-4s %-18s %7s %5s %6s\n", "CODE", "COUNTRY", "SERVERS", "OPEN", "LOAD")
	for _, x := range list {
		fmt.Printf("%-4s %-18s %7d %5d %5d%%\n", x.Code, x.Name, x.Servers, x.Open, pct(x.Load))
	}
	return nil
}

func cmdServers(args []string) error {
	var c commonFlags
	fs := newFlagSet("servers", "list servers, least loaded first", &c)
	country := fs.String("country", "", "only this country code (see the countries command)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	ctx, stop := notifyCtx()
	defer stop()
	_, manifest, err := account(ctx, c)
	if err != nil {
		return err
	}
	all := listServers(manifest)
	var list []server
	for _, s := range all {
		if *country == "" || strings.EqualFold(s.Country, *country) {
			list = append(list, s)
		}
	}
	sortByLoad(list)
	if jsonOut {
		type row struct {
			Name        string `json:"name"`
			Country     string `json:"country"`
			Location    string `json:"location"`
			Users       int    `json:"users"`
			LoadPercent int    `json:"load_percent"`
			Open        bool   `json:"open"`
		}
		rows := make([]row, 0, len(list))
		for _, s := range list {
			rows = append(rows, row{s.Name, s.Country, s.Location, s.Users, pct(s.load()), !s.closed})
		}
		return printJSON(rows)
	}
	fmt.Printf("%-16s %-3s %-22s %5s %5s\n", "SERVER", "CC", "LOCATION", "USERS", "LOAD")
	for _, s := range list {
		note := ""
		if s.closed {
			note = "  (closed)"
		}
		fmt.Printf("%-16s %-3s %-22s %5d %4d%%%s\n", s.Name, s.Country, s.Location, s.Users, pct(s.load()), note)
	}
	return nil
}

func cmdSocks(args []string) error {
	var c commonFlags
	fs := newFlagSet("socks", "log in and serve a SOCKS5 proxy through AirVPN", &c)
	conf := fs.String("c", "", "WireGuard config file from the AirVPN Config Generator (instead of logging in)")
	srvName := fs.String("s", "", "server name (default: least loaded open server)")
	country := fs.String("country", "", "country code: least loaded open server there")
	keyName := fs.String("key", "", "device key name on the account (default: first)")
	port := fs.Int("port", 0, "WireGuard UDP port (default: from AirVPN)")
	listen := fs.String("l", "127.0.0.1:1080", "SOCKS5 listen address (loopback only)")
	check := fs.Bool("check", false, "exit 0 as soon as the tunnel is up (verifies login, server and network)")
	verbose := fs.Bool("v", false, "verbose WireGuard logging")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := checkLoopback(*listen); err != nil {
		return err
	}
	ctx, stop := notifyCtx()
	defer stop()

	var cfg *wgConfig
	info := session{}
	if *conf != "" {
		var err error
		if cfg, err = loadConfigFile(*conf); err != nil {
			return err
		}
		info.Server = "config file"
	} else {
		user, manifest, err := account(ctx, c)
		if err != nil {
			return err
		}
		srv, err := pickServer(listServers(manifest), *srvName, *country)
		if err != nil {
			return err
		}
		if cfg, err = buildConfig(user, manifest, srv, *keyName, *port); err != nil {
			return err
		}
		info = session{Server: srv.Name, Country: srv.Country, Location: srv.Location}
	}
	return serveProxy(ctx, cfg, info, *listen, *verbose, *check)
}

func loadConfigFile(path string) (*wgConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(os.Stderr, "warning: %s holds your private key and is readable by others (chmod 600)\n", path)
	}
	cfg, err := parseConfig(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// session describes the chosen server for messages.
type session struct{ Server, Country, Location string }

const handshakeWait = 20 * time.Second

// serveProxy runs the tunnel and the SOCKS listener until ctx ends. With
// jsonOut or check it fails (exit 1) when the VPN never answers; for a human
// it only warns and keeps trying.
func serveProxy(ctx context.Context, cfg *wgConfig, info session, listen string, verbose, check bool) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	level := device.LogLevelError
	if verbose {
		level = device.LogLevelVerbose
	}
	t, err := startTunnel(ctx, cfg, level)
	if err != nil {
		return err
	}
	defer t.Close()
	l, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	go func() { <-ctx.Done(); l.Close() }()
	fmt.Fprintf(os.Stderr, "connecting to %s via %s ...\n", orDefault(info.Server, "VPN server"), cfg.endpoint)

	failed := make(chan error, 1)
	go func() {
		if !waitHandshake(ctx, t, handshakeWait) {
			if ctx.Err() != nil {
				return
			}
			err := errors.New("no handshake with the VPN server after 20s (check the server, the UDP port and your network)")
			if jsonOut || check {
				failed <- err
				cancel()
			} else {
				fmt.Fprintln(os.Stderr, "warning:", err)
			}
			return
		}
		announceReady(os.Stdout, l.Addr().String(), cfg, info)
		if check {
			cancel()
		}
	}()

	serveSOCKS(l, t.DialContext, func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) })
	select {
	case err := <-failed:
		return err
	default:
		return nil
	}
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func announceReady(w io.Writer, listen string, cfg *wgConfig, info session) {
	if jsonOut {
		b, _ := json.Marshal(map[string]any{
			"event": "ready", "listen": listen, "server": info.Server, "country": info.Country,
			"endpoint": cfg.endpoint, "tunnel_address": cfg.addresses[0].String(),
		})
		fmt.Fprintln(w, string(b))
		return
	}
	fmt.Fprintf(w, "ready: SOCKS5 proxy on %s via %s (tunnel address %s)\n", listen, orDefault(info.Server, cfg.endpoint), cfg.addresses[0])
}

// waitHandshake polls until WireGuard completed a handshake, or false after d.
func waitHandshake(ctx context.Context, t *tunnel, d time.Duration) bool {
	deadline := time.After(d)
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-deadline:
			return false
		case <-tick.C:
			if !t.lastHandshake().IsZero() {
				return true
			}
		}
	}
}

func checkLoopback(listen string) error {
	host, _, err := splitHostPort(listen)
	if err != nil {
		return fmt.Errorf("listen address: %w", err)
	}
	if host == "localhost" {
		return nil
	}
	if a, err := netip.ParseAddr(host); err == nil && a.IsLoopback() {
		return nil
	}
	return fmt.Errorf("refusing to listen on %q: the proxy has no authentication, use a loopback address", listen)
}
