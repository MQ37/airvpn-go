# airvpn-go

Logs in to your AirVPN account and serves a local SOCKS5 proxy. Point a browser
(or `curl --socks5-hostname`) at it and only that traffic goes through AirVPN.
No root, no TUN device, no system routes: WireGuard runs in userspace inside
the process (wireguard-go netstack). Status: local only, not published.

Everything builds and runs in rootless podman, nothing on the host.

## Install

```
./build.sh install     # builds in podman; puts `airvpn-go` in ~/.local/bin
```

The installed `airvpn-go` is a small launcher that runs the binary in a
read-only, capability-less podman container with host networking (so the proxy
port is reachable by your browser). Other targets: `./build.sh build|test|tidy`.

## For humans

```
airvpn-go              # no arguments: interactive menu
```

You are asked for login and password (hidden), then pick a country (number, or
type a code like `nl`; Enter = best server anywhere), a server (Enter = least
loaded), a device key if the account has several, and the listen address
(Enter = `127.0.0.1:1080`). `q` quits any menu. Then set the browser to SOCKS v5
`127.0.0.1:1080` and tick "Proxy DNS when using SOCKS v5" so names resolve inside
the tunnel. Ctrl+C stops the proxy.

## For scripts and agents

Never prompts when stdin is not a terminal or with `-no-input`. stdout is data
only, stderr is logs and errors. Exit codes: 0 ok, 1 failure, 2 usage.

```
airvpn-go countries [-json]
airvpn-go servers [-country nl] [-json]
airvpn-go socks [-country nl | -s Alpha] [-key NAME] [-port N] [-l 127.0.0.1:1080] [-json] [-check] [-v]
airvpn-go socks -c airvpn.conf        # Config Generator file instead of logging in
airvpn-go forget                      # delete saved credentials
airvpn-go help                        # and -h on every command
```

- `-json` on `countries`/`servers` prints a JSON array. On `socks` it prints one line
  `{"event":"ready","listen":"127.0.0.1:1080","server":"...","country":"nl","endpoint":"...","tunnel_address":"..."}`
  on stdout once the WireGuard handshake is done and the port is listening; errors are
  `{"error":"..."}` on stderr.
- `-check` exits 0 as soon as the tunnel is up: a quick "do my credentials, server and
  network work" test. Without `-json`/`-check` a missing handshake only warns.
- Run `socks` in the background and wait for the ready line.

## Credentials

Login: `-login` or `AIRVPN_LOGIN`. Password: `AIRVPN_PASSWORD` or `-password-file`,
never a flag. Missing on a terminal: you are asked (password hidden).

**Saving.** After a successful login with typed credentials you are asked
`Save? [y/N]`; Enter means no. It asks every time you type credentials that are not
already saved, and never when they came from the environment or a file, with no
terminal, or with `-json`. Saved credentials are used automatically from then on,
also by scripts. They are stored **unencrypted** in
`~/.config/airvpn-go/credentials` (JSON, file 0600, directory 0700; a file other users
can read is refused). `airvpn-go forget` deletes it. If a saved login is rejected the
error says so. `AIRVPN_CONFIG_DIR` / `XDG_CONFIG_HOME` move the directory.

## How login works

Same envelope as Eddie (GPL-3.0, reimplemented, no code copied): form POST of `s` (random
AES-256 key+IV wrapped with AirVPN's RSA-4096 public key, PKCS#1 v1.5) and `d` (parameters
`act`, `login`, `password`, ... AES-CBC encrypted). The answer is XML encrypted with the same
key. `act=user` returns the device keys (`wg_private_key`, `wg_ipv4`, `wg_dns_ipv4`,
`wg_preshared`, ...) and the server's `wg_public_key`; `act=manifest` returns servers and modes.
Bootstrap endpoints are the ones shipped with Eddie, tried in order. WireGuard keys stay in
memory; nothing but the optional credentials file is written to disk.

## Status and limits

- Tested offline against a fake AirVPN API plus a real in-process WireGuard peer, and the
  prompts and Ctrl+C through a real terminal. A real run (2026-10-24) logged in, picked a
  server and completed the WireGuard handshake, so the login protocol, server list and entry
  address handling work. Not yet confirmed: 2FA accounts, and traffic volume over long runs.
- Ctrl+C stops cleanly (open connections are closed); a second Ctrl+C exits at once.
- Point clients at the **SOCKS** host, not at an HTTP/HTTPS proxy field: an HTTP client gets
  a plain-text hint and one log line.
- SOCKS5 CONNECT only (no UDP associate, no auth). Listens on loopback only; any local
  process can use it.
- If the tunnel drops the proxy simply fails (no leak path); it does not switch servers.
- Only dependency: `golang.zx2c4.com/wireguard` (official, pinned commit) and what it requires.
