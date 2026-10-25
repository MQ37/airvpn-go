// airvpn-go-socks logs in to an AirVPN account (or reads a WireGuard config) and
// serves a local SOCKS5 proxy. The tunnel runs in userspace inside this
// process: no root, no TUN device, no system routes. Only programs that use the
// proxy go through the VPN.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

const usage = `usage:
  airvpn-go-socks servers [-login L] [-password-file F]
  airvpn-go-socks socks   [-login L] [-password-file F] [-s SERVER] [-key NAME] [-port N] [-l 127.0.0.1:1080] [-v]
  airvpn-go-socks socks   -c airvpn.conf [-l 127.0.0.1:1080] [-v]

The password is read from AIRVPN_PASSWORD, -password-file, or a hidden prompt.
The login can also come from AIRVPN_LOGIN.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "servers":
		err = cmdServers(os.Args[2:])
	case "socks":
		err = cmdSocks(os.Args[2:])
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "airvpn-go-socks:", err)
		os.Exit(1)
	}
}

func cmdServers(args []string) error {
	fs := flag.NewFlagSet("servers", flag.ExitOnError)
	login := fs.String("login", "", "AirVPN account login")
	pwFile := fs.String("password-file", "", "file holding the account password")
	fs.Parse(args)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	l, p, err := credentials(*login, *pwFile)
	if err != nil {
		return err
	}
	c, err := newAPIClient(l, p)
	if err != nil {
		return err
	}
	if _, err := c.fetch(ctx, "user"); err != nil { // validates the login
		return err
	}
	m, err := c.fetch(ctx, "manifest")
	if err != nil {
		return err
	}
	fmt.Printf("%-16s %-3s %-22s %5s %5s\n", "SERVER", "CC", "LOCATION", "USERS", "LOAD")
	for _, s := range listServers(m) {
		note := ""
		if s.closed {
			note = "  (closed)"
		}
		fmt.Printf("%-16s %-3s %-22s %5d %4.0f%%%s\n", s.Name, s.Country, s.Location, s.Users, 100*s.load(), note)
	}
	return nil
}

func cmdSocks(args []string) error {
	fs := flag.NewFlagSet("socks", flag.ExitOnError)
	conf := fs.String("c", "", "WireGuard config file from the AirVPN Config Generator (instead of logging in)")
	login := fs.String("login", "", "AirVPN account login")
	pwFile := fs.String("password-file", "", "file holding the account password")
	srvName := fs.String("s", "", "server name (default: least loaded open server)")
	keyName := fs.String("key", "", "device key name on the account (default: first)")
	port := fs.Int("port", 0, "WireGuard UDP port (default: from AirVPN)")
	listen := fs.String("l", "127.0.0.1:1080", "SOCKS5 listen address (loopback only)")
	verbose := fs.Bool("v", false, "verbose WireGuard logging")
	fs.Parse(args)
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if err := checkLoopback(*listen); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var cfg *wgConfig
	var err error
	if *conf != "" {
		cfg, err = loadConfigFile(*conf)
	} else {
		cfg, err = loginConfig(ctx, *login, *pwFile, *srvName, *keyName, *port)
	}
	if err != nil {
		return err
	}

	level := device.LogLevelError
	if *verbose {
		level = device.LogLevelVerbose
	}
	t, err := startTunnel(ctx, cfg, level)
	if err != nil {
		return err
	}
	defer t.Close()

	l, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	go func() { <-ctx.Done(); l.Close() }()
	fmt.Printf("SOCKS5 proxy on %s via %s (tunnel address %s)\n", l.Addr(), cfg.endpoint, cfg.addresses[0])
	go announceHandshake(ctx, t)

	serveSOCKS(l, t.DialContext, func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) })
	return nil
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

// loginConfig logs in, picks a server and returns the WireGuard settings. The
// keys stay in memory; nothing is written to disk.
func loginConfig(ctx context.Context, login, pwFile, srvName, keyName string, port int) (*wgConfig, error) {
	l, p, err := credentials(login, pwFile)
	if err != nil {
		return nil, err
	}
	c, err := newAPIClient(l, p)
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(os.Stderr, "logging in to AirVPN ...")
	user, err := c.fetch(ctx, "user")
	if err != nil {
		return nil, err
	}
	manifest, err := c.fetch(ctx, "manifest")
	if err != nil {
		return nil, err
	}
	srv, err := pickServer(listServers(manifest), srvName)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "server %s (%s, %.0f%% load)\n", srv.Name, srv.Location, 100*srv.load())
	return buildConfig(user, manifest, srv, keyName, port)
}

// announceHandshake reports once whether the VPN server answered.
func announceHandshake(ctx context.Context, t *tunnel) {
	deadline := time.After(20 * time.Second)
	for tick := time.NewTicker(250 * time.Millisecond); ; {
		select {
		case <-ctx.Done():
			return
		case <-deadline:
			fmt.Fprintln(os.Stderr, "warning: no handshake with the VPN server after 20s (check the config, endpoint and your network)")
			return
		case <-tick.C:
			if !t.lastHandshake().IsZero() {
				fmt.Println("tunnel up: WireGuard handshake completed")
				return
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
