package wireproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	"github.com/sourcegraph/conc"
	"golang.zx2c4.com/wireguard/device"
)

const proxyAuthHeaderKey = "Proxy-Authorization"

type HTTPServer struct {
	config *HTTPConfig

	auth CredentialValidator
	dev  *DeviceConfig
	// dial func(network, address string) (net.Conn, error)

	authRequired bool
}

func (s *HTTPServer) authenticate(req *http.Request) (int, error) {
	if !s.authRequired {
		return 0, nil
	}

	auth := req.Header.Get(proxyAuthHeaderKey)
	if auth != "" {
		enc := strings.TrimPrefix(auth, "Basic ")
		str, err := base64.StdEncoding.DecodeString(enc)
		if err != nil {
			return http.StatusNotAcceptable, fmt.Errorf("decode username and password failed: %w", err)
		}
		pairs := bytes.SplitN(str, []byte(":"), 2)
		if len(pairs) != 2 {
			return http.StatusLengthRequired, fmt.Errorf("username and password format invalid")
		}
		if s.auth.Valid(string(pairs[0]), string(pairs[1])) {
			return 0, nil
		}
		return http.StatusUnauthorized, fmt.Errorf("username and password not matching")
	}

	return http.StatusProxyAuthRequired, fmt.Errorf(http.StatusText(http.StatusProxyAuthRequired))
}

func (s *HTTPServer) serve(conn net.Conn) {
	var rd = bufio.NewReader(conn)
	req, err := http.ReadRequest(rd)
	deadline := time.Now().Add(20 * time.Second)
	_ = conn.SetDeadline(deadline)

	defer conn.Close()
	if err != nil {
		log.Printf("read request failed: %s\n", err)
		return
	}

	code, err := s.authenticate(req)
	if err != nil {
		_ = responseWith(req, code).Write(conn)
		log.Println(err)
		return
	}

	tun, err := StartWireguard(s.dev, device.LogLevelVerbose)
	if err != nil {
		log.Fatal(err)
	}
	defer tun.Dev.Close()
	// tun.StartPingIPs()
	ps := &ProxyServer{
		vt: tun,
	}
	var peer net.Conn
	switch req.Method {
	case http.MethodConnect:

		peer, err = ps.handleConn(req, conn)
	case http.MethodGet:
		peer, err = ps.handle(req)
	default:
		_ = responseWith(req, http.StatusMethodNotAllowed).Write(conn)
		log.Printf("unsupported protocol: %s\n", req.Method)
		return
	}
	if err != nil {
		log.Printf("dial proxy failed: %s\n", err)
		return
	}
	if peer == nil {
		log.Println("dial proxy failed: peer nil")
		return
	}
	_ = peer.SetDeadline(deadline)

	wg := conc.NewWaitGroup()
	wg.Go(func() {
		_, err = io.Copy(conn, peer)
	})
	wg.Go(func() {
		defer peer.Close()
		_, err = io.Copy(peer, rd)
	})
	wg.Wait()
}

// ListenAndServe is used to create a listener and serve on it
func (s *HTTPServer) ListenAndServe(network, addr string) error {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var err error
			c.Control(func(fd uintptr) {
				err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			})
			return err
		},
	}
	server, err := lc.Listen(context.Background(), network, addr)
	if err != nil {
		return fmt.Errorf("listen tcp failed: %w", err)
	}
	defer func(server net.Listener) {
		_ = server.Close()
	}(server)
	for {
		conn, err := server.Accept()
		if err != nil {
			return fmt.Errorf("accept request failed: %w", err)
		}
		go func(conn net.Conn) {
			s.serve(conn)
		}(conn)
	}
}
