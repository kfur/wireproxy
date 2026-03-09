package wireproxy

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

type ProxyServer struct {
	vt *VirtualTun
	// dial func(network, address string) (net.Conn, error)
}

func (s *ProxyServer) handleConn(req *http.Request, conn net.Conn) (peer net.Conn, err error) {
	addr := req.Host
	if !strings.Contains(addr, ":") {
		port := "443"
		addr = net.JoinHostPort(addr, port)
	}

	peer, err = s.vt.Tnet.Dial("tcp", addr)
	if err != nil {
		return peer, fmt.Errorf("tun tcp dial failed: %w", err)
	}

	_, err = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	if err != nil {
		_ = peer.Close()
		peer = nil
	}

	return
}

func (s *ProxyServer) handle(req *http.Request) (peer net.Conn, err error) {
	addr := req.Host
	if !strings.Contains(addr, ":") {
		port := "80"
		addr = net.JoinHostPort(addr, port)
	}

	peer, err = s.vt.Tnet.Dial("tcp", addr)
	if err != nil {
		return peer, fmt.Errorf("tun tcp dial failed: %w", err)
	}

	err = req.Write(peer)
	if err != nil {
		_ = peer.Close()
		peer = nil
		return peer, fmt.Errorf("conn write failed: %w", err)
	}

	return
}
