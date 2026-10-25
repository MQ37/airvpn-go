package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
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
//
// When l is closed it stops everything: pending dials are cancelled and every
// open connection is closed, so shutdown (Ctrl+C) never waits for a browser's
// keep-alive connections.
func serveSOCKS(l net.Listener, dial dialFunc, logf func(string, ...any)) {
	ctx, cancel := context.WithCancel(context.Background())
	reg := &connSet{m: map[net.Conn]struct{}{}}
	sem := make(chan struct{}, maxConns)
	var wg sync.WaitGroup
	var warnedHTTP atomic.Bool
	defer func() {
		cancel()
		reg.closeAll()
		wg.Wait()
	}()
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
		if !reg.add(c) {
			c.Close()
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			defer reg.del(c)
			defer c.Close()
			err := handleSOCKS(ctx, c, dial, reg)
			switch {
			case err == nil || ctx.Err() != nil:
			case errors.Is(err, errHTTPClient):
				if warnedHTTP.CompareAndSwap(false, true) {
					logf("a client speaks the HTTP proxy protocol to this SOCKS5 port (%s): set the browser's SOCKS Host (SOCKS v5), not its HTTP/HTTPS proxy. Further such requests are not logged.", c.RemoteAddr())
				}
			default:
				logf("socks %s: %v", c.RemoteAddr(), err)
			}
		}()
	}
}

// connSet tracks open connections so shutdown can close them all.
type connSet struct {
	mu     sync.Mutex
	m      map[net.Conn]struct{}
	closed bool
}

func (s *connSet) add(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.m[c] = struct{}{}
	return true
}

func (s *connSet) del(c net.Conn) {
	s.mu.Lock()
	delete(s.m, c)
	s.mu.Unlock()
}

func (s *connSet) closeAll() {
	s.mu.Lock()
	s.closed = true
	for c := range s.m {
		c.Close()
	}
	s.mu.Unlock()
}

var errHTTPClient = errors.New("HTTP proxy request on a SOCKS5 port")

// httpProxyReply is what a browser configured with the wrong proxy type sees.
const httpProxyReply = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n" +
	"This is a SOCKS5 proxy, not an HTTP proxy.\r\nIn the browser set \"SOCKS Host\" (SOCKS v5) to this address and leave the HTTP/HTTPS proxy fields empty.\r\n"

func handleSOCKS(ctx context.Context, c net.Conn, dial dialFunc, reg *connSet) error {
	c.SetDeadline(time.Now().Add(handshakeTimeout))

	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return err
	}
	if hdr[0] != 5 {
		// An upper-case letter is the start of an HTTP method (CONNECT, GET, ...).
		if hdr[0] >= 'A' && hdr[0] <= 'Z' {
			c.Write([]byte(httpProxyReply))
			return errHTTPClient
		}
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

	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	up, err := dial(dctx, "tcp", target)
	if err != nil {
		reply(c, replyCode(err))
		return fmt.Errorf("connect %s: %w", target, err)
	}
	defer up.Close()
	if !reg.add(up) {
		return errors.New("shutting down")
	}
	defer reg.del(up)
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
