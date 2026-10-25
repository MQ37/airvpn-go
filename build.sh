#!/usr/bin/env bash
# All work happens in rootless podman. Nothing is built or run on the host.
#   ./build.sh build    -> static binary in ./dist/airvpn-go
#   ./build.sh test     -> unit + end-to-end tests (no network, RAM-only scratch)
#   ./build.sh tidy     -> refresh go.mod/go.sum (only step that needs the network)
#   ./build.sh install  -> binary in ~/.local/share/airvpn-go, podman launcher `airvpn-go` in ~/.local/bin
#   ./build.sh run socks|servers [flags]  -> run in a container, SOCKS on 127.0.0.1:1080 (CONF=file for -c)
set -euo pipefail
cd "$(dirname "$0")"
IMG=localhost/airvpn-go-build

case "${1:-}" in
tidy)
	podman run --rm -v "$PWD":/app -w /app --tmpfs /tmp:rw,exec,size=1g \
		-e GOCACHE=/tmp/gocache -e GOPATH=/tmp/gopath -e GOFLAGS=-buildvcs=false -e HOME=/tmp \
		docker.io/library/golang:1.25-alpine sh -c 'go mod tidy && go mod verify'
	;;
build)
	podman build -q -t "$IMG" --target build .
	rm -rf dist && mkdir dist
	podman build -q --target out -o type=local,dest=dist .
	ls -l dist/airvpn-go
	;;
test)
	podman build -q -t "$IMG" --target build .
	podman run --rm --network none --read-only --memory 2g \
		--tmpfs /tmp:rw,exec,size=1g -e GOCACHE=/tmp/gocache -e HOME=/tmp \
		"$IMG" go test -count=1 -v -timeout 5m ./...
	;;
run)
	shift
	test -f dist/airvpn-go || { echo "run ./build.sh build first" >&2; exit 1; }
	mounts=(-v "$PWD/dist/airvpn-go":/airvpn-go:ro)
	# CONF=/path/airvpn.conf mounts a Config Generator file at /etc/airvpn.conf (use -c /etc/airvpn.conf)
	[ -n "${CONF:-}" ] && mounts+=(-v "$(realpath "$CONF")":/etc/airvpn.conf:ro)
	# host network so 127.0.0.1:1080 is reachable by the browser; read-only, no caps.
	# AIRVPN_LOGIN / AIRVPN_PASSWORD are passed by name only (never on a command line);
	# -it gives the hidden password prompt when AIRVPN_PASSWORD is unset.
	exec podman run --rm -it --network host --read-only --cap-drop all \
		--security-opt no-new-privileges --memory 512m \
		-e AIRVPN_LOGIN -e AIRVPN_PASSWORD "${mounts[@]}" \
		docker.io/library/alpine:3.21 /airvpn-go "$@"
	;;
install)
	"$0" build
	share="${XDG_DATA_HOME:-$HOME/.local/share}/airvpn-go"
	mkdir -p "$share" "$HOME/.local/bin"
	install -m 0755 dist/airvpn-go "$share/airvpn-go"
	install -m 0755 launcher.sh "$HOME/.local/bin/airvpn-go"
	echo "installed: $HOME/.local/bin/airvpn-go (runs in podman)"
	;;
*)
	sed -n '2,8p' "$0"
	exit 2
	;;
esac
