# airvpn-go-socks

Logs in to your AirVPN account and serves a local SOCKS5 proxy. Point a browser
(or `curl --socks5-hostname`) at it and only that traffic goes through AirVPN.
No root, no TUN device, no system routes: WireGuard runs in userspace inside
the process (wireguard-go netstack). Status: local only, not published.

Everything builds and runs in rootless podman (`./build.sh`), nothing on the host.

```
./build.sh build                      # dist/airvpn-go-socks (static)
./build.sh test                       # unit + end-to-end tests, no network, RAM scratch
./build.sh run servers                # log in, list servers (prompts for login/password)
./build.sh run socks                  # log in, least loaded server, proxy on 127.0.0.1:1080
./build.sh run socks -s Alpha -key Default -port 47107
CONF=airvpn.conf ./build.sh run socks -c /etc/airvpn.conf   # Config Generator file instead of login
```

Firefox: Settings, Network, Manual proxy, SOCKS host 127.0.0.1 port 1080, SOCKS v5,
tick "Proxy DNS when using SOCKS v5" (names are then resolved inside the tunnel).

## Credentials

Login from `-login` or `AIRVPN_LOGIN`. Password from `AIRVPN_PASSWORD`, `-password-file`,
or a hidden prompt; never a flag. Nothing is written to disk: the account's WireGuard key
stays in memory. Do not put the password into shell history (`read -rs AIRVPN_PASSWORD; export AIRVPN_PASSWORD`).

## How login works

Same envelope as Eddie (GPL-3.0, reimplemented, no code copied): form POST of `s` (random
AES-256 key+IV wrapped with AirVPN's RSA-4096 public key, PKCS#1 v1.5) and `d` (parameters
`act`, `login`, `password`, ... AES-CBC encrypted). The answer is XML encrypted with the same
key. `act=user` returns the device keys (`wg_private_key`, `wg_ipv4`, `wg_dns_ipv4`,
`wg_preshared`, ...) and the server's `wg_public_key`; `act=manifest` returns servers and modes.
Bootstrap endpoints are the ones shipped with Eddie, tried in order.

## Status and limits

- Tested offline against a fake AirVPN API plus a real in-process WireGuard peer. **Not yet
  run against the real AirVPN API**: the first real login may expose protocol details (AES
  mode, `ips_entry`/`entry_index` use, 2FA) that the fake cannot.
- SOCKS5 CONNECT only (no UDP associate, no auth). Listens on loopback only; any local
  process can use it.
- If the tunnel drops the proxy simply fails (no leak path), it does not reconnect to
  another server by itself.
- Only dependency: `golang.zx2c4.com/wireguard` (official, pinned commit) and what it requires.
