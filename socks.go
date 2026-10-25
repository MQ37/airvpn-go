package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"
)

type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

const (
	maxConns         = 256
	handshakeTimeout = 10 * time.Second
	dialTimeout      = 20 * time.Second
)

// SOCKS5 reply codes (RFC 1928).
const (
	repOK, repFail, repNetUnreach, repHostUnreach = 0, 1, 3, 4
	repRefused, repCmdUnsupported, repAtypUnsupp  = 5, 7, 8
)

// serveSOCKS accepts SOCKS5 clients until l is closed. It supports only
// CONNECT without authentication, and hands every target (including names)
// to dial, so DNS happens wherever dial resolves it.
func serveSOCKS(l net.Listener, dial dialFunc, logf func(string, ...any)) {
	sem := make(chan struct{}, maxConns)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		select {
		case sem <- struct{}{}:
		default:
			c.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			defer c.Close()
			if err := handleSOCKS(c, dial); err != nil {
				logf("socks %s: %v", c.RemoteAddr(), err)
			}
		}()
	}
}

func handleSOCKS(c net.Conn, dial dialFunc) error {
	c.SetDeadline(time.Now().Add(handshakeTimeout))

	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return err
	}
	if hdr[0] != 5 {
		return fmt.Errorf("not SOCKS5 (version %d)", hdr[0])
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}
	noAuth := false
	for _, m := range methods {
		noAuth = noAuth || m == 0
	}
	if !noAuth {
		c.Write([]byte{5, 0xff})
		return errors.New("client offers no 'no auth' method")
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return err
	}

	var req [4]byte
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return err
	}
	if req[0] != 5 {
		return fmt.Errorf("bad request version %d", req[0])
	}
	var host string
	switch req[3] {
	case 1, 4:
		ip := make([]byte, map[byte]int{1: 4, 4: 16}[req[3]])
		if _, err := io.ReadFull(c, ip); err != nil {
			return err
		}
		host = net.IP(ip).String()
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return err
		}
		name := make([]byte, n[0])
		if _, err := io.ReadFull(c, name); err != nil {
			return err
		}
		host = string(name)
	default:
		reply(c, repAtypUnsupp)
		return fmt.Errorf("address type %d unsupported", req[3])
	}
	var pb [2]byte
	if _, err := io.ReadFull(c, pb[:]); err != nil {
		return err
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(pb[0])<<8|int(pb[1])))
	if req[1] != 1 {
		reply(c, repCmdUnsupported)
		return fmt.Errorf("command %d unsupported (CONNECT only)", req[1])
	}

	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	up, err := dial(ctx, "tcp", target)
	if err != nil {
		reply(c, replyCode(err))
		return fmt.Errorf("connect %s: %w", target, err)
	}
	defer up.Close()
	if err := reply(c, repOK); err != nil {
		return err
	}
	c.SetDeadline(time.Time{})

	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
		done <- struct{}{}
	}
	go pipe(up, c)
	go pipe(c, up)
	<-done
	<-done
	return nil
}

func reply(c net.Conn, code byte) error {
	_, err := c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}

func replyCode(err error) byte {
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return repRefused
	case errors.Is(err, syscall.ENETUNREACH):
		return repNetUnreach
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, context.DeadlineExceeded):
		return repHostUnreach
	}
	return repFail
}
