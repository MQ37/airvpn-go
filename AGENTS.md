# Agent instructions

- Podman only: build, test and run through `./build.sh`; never run the binary or Go on the host.
- Keep it minimal: stdlib plus the pinned official wireguard-go only; no new dependencies without the owner's go.
- Never bind a non-loopback address. Never log or write the password or WireGuard keys; credentials only via env, file or hidden prompt.
- Local only: do not publish or push anywhere. Branch is `master`. No AI attribution lines in commits.
- Real AirVPN calls send the owner's account login: only when the owner asks.
- No personal data in code, comments, docs or tests: no names, emails, usernames, machine or host names, paths, or IPs of this machine. Use generic placeholders (127.0.0.1, 10.x, 203.0.113.x).
