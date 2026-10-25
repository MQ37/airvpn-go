package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// tunnel is a userspace WireGuard peer: no TUN device, no root, no routes.
// Only connections dialed through it use the VPN.
type tunnel struct {
	dev *device.Device
	net *netstack.Net
}

func splitHostPort(s string) (string, int, error) {
	host, ps, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(ps)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("bad port %q", ps)
	}
	return host, port, nil
}

// resolveEndpoint resolves the VPN server name over the host network (the
// tunnel does not exist yet), preferring IPv4.
func resolveEndpoint(ctx context.Context, endpoint string) (netip.AddrPort, error) {
	host, port, err := splitHostPort(endpoint)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(a, uint16(port)), nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return netip.AddrPort{}, fmt.Errorf("resolve %s: %v", host, err)
	}
	pick := ips[0]
	for _, ip := range ips {
		if ip.Is4() {
			pick = ip
			break
		}
	}
	return netip.AddrPortFrom(pick.Unmap(), uint16(port)), nil
}

func startTunnel(ctx context.Context, cfg *wgConfig, level int) (*tunnel, error) {
	ep, err := resolveEndpoint(ctx, cfg.endpoint)
	if err != nil {
		return nil, err
	}
	tdev, tnet, err := netstack.CreateNetTUN(cfg.addresses, cfg.dns, cfg.mtu)
	if err != nil {
		return nil, err
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(level, "wg: "))

	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", cfg.privateKey)
	fmt.Fprintf(&b, "public_key=%s\n", cfg.publicKey)
	if cfg.presharedKey != "" {
		fmt.Fprintf(&b, "preshared_key=%s\n", cfg.presharedKey)
	}
	fmt.Fprintf(&b, "endpoint=%s\n", ep)
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", cfg.keepalive)
	for _, a := range cfg.allowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", a)
	}
	if err := dev.IpcSet(b.String()); err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}
	return &tunnel{dev: dev, net: tnet}, nil
}

// DialContext dials through the tunnel. Host names are resolved by the DNS
// servers from the config, inside the tunnel.
func (t *tunnel) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	// Loopback is never the VPN's: the in-tunnel stack drops such packets
	// silently, which would make the client hang instead of failing.
	if host, _, err := net.SplitHostPort(addr); err == nil {
		if ip, err := netip.ParseAddr(host); err == nil && (ip.IsLoopback() || ip.IsUnspecified()) {
			return nil, fmt.Errorf("%s is a local address, not reachable through the tunnel", host)
		}
	}
	return t.net.DialContext(ctx, network, addr)
}

func (t *tunnel) Close() { t.dev.Close() }

// lastHandshake returns the time of the last completed handshake, or the zero
// time if there has been none yet.
func (t *tunnel) lastHandshake() time.Time {
	out, err := t.dev.IpcGet()
	if err != nil {
		return time.Time{}
	}
	for _, l := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(l, "last_handshake_time_sec="); ok {
			if s, err := strconv.ParseInt(v, 10, 64); err == nil && s > 0 {
				return time.Unix(s, 0)
			}
		}
	}
	return time.Time{}
}
