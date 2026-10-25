# Agent instructions

- Podman only: build, test and run through `./build.sh`; never run the binary or Go on the host.
- Keep it minimal: stdlib plus the pinned official wireguard-go only; no new dependencies without the owner's go.
- Never bind a non-loopback address. Never log or print the password or WireGuard keys. The password comes from env, file, a hidden prompt, or the saved-credentials file; it is written to disk only when the user answers the "Save? [y/N]" prompt with y (default no, 0600 file, never from env/file/non-terminal runs).
- Local only: do not publish or push anywhere. Branch is `master`. No AI attribution lines in commits.
- Real AirVPN calls send the owner's account login: only when the owner asks.
- No personal data in code, comments, docs or tests: no names, emails, usernames, machine or host names, paths, or IPs of this machine. Use generic placeholders (127.0.0.1, 10.x, 203.0.113.x).
- Interactive menu for humans, flags + `-json` + exit codes for agents: keep both working; no prompt may ever appear without a terminal.
- Layout: root `main.go` only calls `internal/app.Main()` (it must stay at the root so `go install github.com/MQ37/airvpn-go@latest` works); all code and tests are in `internal/app/`; `packaging/` has the Containerfile and the podman launcher; `build.sh` is the only entry point.
- Smoke tests that start a command must set `AIRVPN_CONFIG_DIR` to an empty temp dir: saved credentials on this machine would otherwise trigger a real login.
