#!/usr/bin/env bash
# Installed as `airvpn-go`. Runs the binary inside rootless podman, never on
# the host. Host network so the SOCKS port is reachable by your browser.
set -euo pipefail
BIN="${XDG_DATA_HOME:-$HOME/.local/share}/airvpn-go/airvpn-go"
[ -f "$BIN" ] || { echo "airvpn-go: $BIN missing, run ./build.sh install" >&2; exit 1; }

# Saved credentials live in one config dir shared by every run (owner-only, see README).
cfg="${XDG_CONFIG_HOME:-$HOME/.config}/airvpn-go"
mkdir -p "$cfg"; chmod 700 "$cfg"

args=() mounts=(-v "$BIN":/airvpn-go:ro -v "$cfg":/config
	-e AIRVPN_CONFIG_DIR=/config -e AIRVPN_CONFIG_SHOWN="$cfg/credentials")
while [ $# -gt 0 ]; do
	case "$1" in
	-c|--c|-password-file|--password-file)
		[ $# -ge 2 ] || { echo "airvpn-go: $1 needs a file" >&2; exit 2; }
		dst=/run/airvpn/conf; [[ $1 == *password* ]] && dst=/run/airvpn/password
		mounts+=(-v "$(realpath "$2")":"$dst":ro)
		args+=("$1" "$dst"); shift 2 ;;
	*) args+=("$1"); shift ;;
	esac
done

tty=-i; [ -t 0 ] && tty=-it
# AIRVPN_LOGIN / AIRVPN_PASSWORD are passed by name only, never on a command line.
exec podman run --rm $tty --network host --read-only --cap-drop all \
	--security-opt no-new-privileges --memory 512m \
	-e AIRVPN_LOGIN -e AIRVPN_PASSWORD "${mounts[@]}" \
	docker.io/library/alpine:3.21 /airvpn-go ${args[@]+"${args[@]}"}
