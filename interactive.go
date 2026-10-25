package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

var errQuit = errors.New("quit")

// ui is a tiny line-based terminal dialog. Questions go to out (stderr in
// real use), so stdout stays free for data.
type ui struct {
	readLine func() (string, error)
	out      io.Writer
}

type option struct {
	Label string
	Keys  []string // typed shortcuts, e.g. a country code
}

// choose shows a numbered menu. Enter picks def, a number picks that entry, a
// typed key picks the entry that lists it, q quits.
func (u *ui) choose(title string, opts []option, def int) (int, error) {
	fmt.Fprintf(u.out, "\n%s\n", title)
	for i, o := range opts {
		mark := " "
		if i == def {
			mark = "*"
		}
		fmt.Fprintf(u.out, " %s%2d) %s\n", mark, i+1, o.Label)
	}
	for tries := 0; tries < 5; tries++ {
		fmt.Fprintf(u.out, "Choice [%d, q quits]: ", def+1)
		line, err := u.readLine()
		if err != nil {
			return 0, fmt.Errorf("no input: %w", err)
		}
		line = strings.TrimSpace(line)
		switch {
		case line == "":
			return def, nil
		case strings.EqualFold(line, "q"):
			return 0, errQuit
		}
		if n, err := strconv.Atoi(line); err == nil && n >= 1 && n <= len(opts) {
			return n - 1, nil
		}
		for i, o := range opts {
			for _, k := range o.Keys {
				if strings.EqualFold(k, line) {
					return i, nil
				}
			}
		}
		fmt.Fprintf(u.out, "Not a valid choice: %q\n", line)
	}
	return 0, errors.New("too many invalid answers")
}

// ask reads a free-text answer with a default.
func (u *ui) ask(prompt, def string, valid func(string) error) (string, error) {
	for tries := 0; tries < 5; tries++ {
		fmt.Fprintf(u.out, "%s [%s]: ", prompt, def)
		line, err := u.readLine()
		if err != nil {
			return "", fmt.Errorf("no input: %w", err)
		}
		if line = strings.TrimSpace(line); line == "" {
			line = def
		}
		if err := valid(line); err != nil {
			fmt.Fprintf(u.out, "%v\n", err)
			continue
		}
		return line, nil
	}
	return "", errors.New("too many invalid answers")
}

type selection struct {
	srv    server
	key    string
	listen string
}

// interactiveSelect walks a human through country, server, device key and
// listen address.
func interactiveSelect(u *ui, user, manifest *document) (selection, error) {
	all := listServers(manifest)
	countries := listCountries(all)
	opts := []option{{Label: "Best server anywhere (lowest load)"}}
	for _, c := range countries {
		if c.Open == 0 {
			continue
		}
		opts = append(opts, option{
			Label: fmt.Sprintf("%-18s %-3s %2d servers, %3d%% load", c.Name, c.Code, c.Open, pct(c.Load)),
			Keys:  []string{c.Code, c.Name},
		})
	}
	if len(opts) == 1 {
		return selection{}, errors.New("no open server found")
	}
	ci, err := u.choose("Country (type a number, or a code like nl):", opts, 0)
	if err != nil {
		return selection{}, err
	}
	country := ""
	if ci > 0 {
		country = strings.ToLower(keyOf(opts[ci], 0))
	}

	list := serversIn(all, country)
	title := "Server:"
	if country != "" {
		title = "Server in " + countryName(country) + ":"
	}
	sopts := []option{{Label: "Best (lowest load)"}}
	for _, s := range list {
		sopts = append(sopts, option{
			Label: fmt.Sprintf("%-16s %-3s %-20s %4d users, %3d%% load", s.Name, s.Country, s.Location, s.Users, pct(s.load())),
			Keys:  []string{s.Name},
		})
	}
	si, err := u.choose(title, sopts, 0)
	if err != nil {
		return selection{}, err
	}
	sel := selection{srv: list[0]}
	if si > 0 {
		sel.srv = list[si-1]
	}

	if len(user.Keys) > 1 {
		kopts := make([]option, len(user.Keys))
		for i, k := range user.Keys {
			kopts[i] = option{Label: k.get("name"), Keys: []string{k.get("name")}}
		}
		ki, err := u.choose("Device key:", kopts, 0)
		if err != nil {
			return selection{}, err
		}
		sel.key = user.Keys[ki].get("name")
	}

	sel.listen, err = u.ask("\nListen address (loopback only)", "127.0.0.1:1080", checkLoopback)
	return sel, err
}

func keyOf(o option, i int) string { return o.Keys[i] }

func cmdMenu(args []string) error {
	var c commonFlags
	fs := newFlagSet("menu", "interactive menu: pick a country and server, then run the proxy", &c)
	verbose := fs.Bool("v", false, "verbose WireGuard logging")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if noInput || !isTerminal(os.Stdin) {
		return errors.New("the menu needs a terminal; use the socks command with flags instead (airvpn-go help)")
	}
	ctx, stop := notifyCtx()
	defer stop()

	fmt.Fprintln(os.Stderr, "airvpn-go: SOCKS5 proxy through AirVPN (userspace WireGuard, no root)")
	user, manifest, err := account(ctx, c)
	if err != nil {
		return err
	}
	u := &ui{readLine: func() (string, error) { return readLine(os.Stdin) }, out: os.Stderr}
	sel, err := interactiveSelect(u, user, manifest)
	if err != nil {
		return err
	}
	cfg, err := buildConfig(user, manifest, sel.srv, sel.key, 0)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "\nUsing %s (%s, %s). Ctrl+C stops the proxy.\n", sel.srv.Name, countryName(sel.srv.Country), sel.srv.Location)
	fmt.Fprintf(os.Stderr, "Browser: SOCKS v5 host %s, tick \"Proxy DNS when using SOCKS v5\".\n\n", sel.listen)
	return serveProxy(ctx, cfg, session{sel.srv.Name, sel.srv.Country, sel.srv.Location}, sel.listen, *verbose, false)
}
