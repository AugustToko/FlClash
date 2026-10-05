package inspectionruntime

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	MaxClients         = 16
	MaxConnectHeader   = 8192
	SessionLifetime    = 10 * time.Minute
	ConnectionLifetime = 120 * time.Second
	HandshakeTimeout   = 5 * time.Second
)

type Config struct {
	ID        string
	Authorize func(context.Context, string) error
	Leaf      func(context.Context, string) (*tls.Certificate, error)
	Dial      func(context.Context, string, string) (net.Conn, error)
	Roots     *x509.CertPool
}

type Status struct {
	ID         string    `json:"id"`
	State      string    `json:"state"`
	Address    string    `json:"address"`
	ExpiresAt  time.Time `json:"expiresAt"`
	Active     int       `json:"active"`
	Accepted   uint64    `json:"accepted"`
	Completed  uint64    `json:"completed"`
	Failed     uint64    `json:"failed"`
	Uploaded   uint64    `json:"uploaded"`
	Downloaded uint64    `json:"downloaded"`
}

type Runtime struct {
	config     Config
	id         string
	address    string
	expiresAt  time.Time
	authHash   [32]byte
	ctx        context.Context
	cancel     context.CancelFunc
	listener   net.Listener
	mu         sync.Mutex
	clients    map[net.Conn]context.CancelFunc
	accepted   uint64
	completed  uint64
	failed     uint64
	uploaded   uint64
	downloaded uint64
	done       chan struct{}
	workers    sync.WaitGroup
	stopOnce   sync.Once
}

func Start(config Config) (*Runtime, string, error) {
	if config.Authorize == nil || config.Leaf == nil || config.Dial == nil {
		return nil, "", errors.New("inspection runtime requires authorization, leaf and routed dial callbacks")
	}
	var entropy [48]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return nil, "", errors.New("inspection runtime entropy unavailable")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, "", errors.New("inspection loopback listener unavailable")
	}
	id := hex.EncodeToString(entropy[:16])
	if config.ID != "" {
		decoded, decodeErr := hex.DecodeString(config.ID)
		if decodeErr != nil || len(decoded) != 16 || strings.ToLower(config.ID) != config.ID {
			_ = listener.Close()
			return nil, "", errors.New("invalid runtime identity")
		}
		id = config.ID
	}
	password := hex.EncodeToString(entropy[16:])
	expiresAt := time.Now().UTC().Add(SessionLifetime)
	ctx, cancel := context.WithDeadline(context.Background(), expiresAt)
	r := &Runtime{
		config: config, id: id,
		address: listener.Addr().String(), expiresAt: expiresAt,
		authHash: sha256.Sum256([]byte("Basic " + base64.StdEncoding.EncodeToString([]byte("flclash:"+password)))),
		ctx:      ctx, cancel: cancel, listener: listener,
		clients: make(map[net.Conn]context.CancelFunc), done: make(chan struct{}),
	}
	context.AfterFunc(ctx, r.Stop)
	go r.accept()
	return r, password, nil
}

func (r *Runtime) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	state := "running"
	if r.ctx.Err() != nil {
		state = "stopped"
	}
	return Status{
		ID: r.id, State: state, Address: r.address, ExpiresAt: r.expiresAt,
		Active: len(r.clients), Accepted: r.accepted, Completed: r.completed,
		Failed: r.failed, Uploaded: r.uploaded, Downloaded: r.downloaded,
	}
}

func (r *Runtime) Stop() {
	r.stopOnce.Do(func() {
		r.cancel()
		_ = r.listener.Close()
		r.mu.Lock()
		for conn, cancel := range r.clients {
			cancel()
			_ = conn.Close()
		}
		r.mu.Unlock()
	})
}

func (r *Runtime) Wait(ctx context.Context) error {
	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *Runtime) accept() {
	defer func() {
		if recover() != nil {
			r.Stop()
		}
		r.workers.Wait()
		close(r.done)
	}()
	for {
		conn, err := r.listener.Accept()
		if err != nil {
			r.Stop()
			return
		}
		r.mu.Lock()
		if r.ctx.Err() != nil || len(r.clients) >= MaxClients {
			r.mu.Unlock()
			_ = conn.Close()
			continue
		}
		ctx, cancel := context.WithTimeout(r.ctx, ConnectionLifetime)
		r.clients[conn] = cancel
		r.accepted++
		r.workers.Add(1)
		r.mu.Unlock()
		go r.serve(ctx, cancel, conn)
	}
}

func (r *Runtime) serve(ctx context.Context, cancel context.CancelFunc, conn net.Conn) {
	var failure error
	defer r.workers.Done()
	defer func() {
		if recover() != nil {
			failure = errors.New("inspection connection failed")
		}
		cancel()
		_ = conn.Close()
		r.mu.Lock()
		delete(r.clients, conn)
		if failure != nil {
			r.failed++
		} else {
			r.completed++
		}
		r.mu.Unlock()
	}()
	failure = r.exchange(ctx, conn)
}

func readConnect(reader *bufio.Reader) (*http.Request, error) {
	var header bytes.Buffer
	for header.Len() <= MaxConnectHeader {
		line, err := reader.ReadSlice('\n')
		if err != nil || len(line) < 2 || line[len(line)-2] != '\r' || header.Len()+len(line) > MaxConnectHeader {
			return nil, errors.New("invalid CONNECT header")
		}
		header.Write(line)
		if bytes.Equal(line, []byte("\r\n")) {
			request, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(header.Bytes())))
			if err != nil {
				return nil, errors.New("invalid CONNECT request")
			}
			hostCount := 0
			for _, raw := range strings.Split(header.String(), "\r\n")[1:] {
				if raw == "" {
					continue
				}
				if raw[0] == ' ' || raw[0] == '\t' {
					return nil, errors.New("folded CONNECT header is unsupported")
				}
				name, value, ok := strings.Cut(raw, ":")
				if !ok {
					return nil, errors.New("invalid CONNECT field")
				}
				if strings.EqualFold(name, "Host") {
					hostCount++
					if strings.TrimSpace(value) != request.RequestURI {
						return nil, errors.New("CONNECT Host mismatch")
					}
				}
				if strings.EqualFold(name, "Content-Length") || strings.EqualFold(name, "Transfer-Encoding") {
					return nil, errors.New("CONNECT body framing is unsupported")
				}
			}
			if hostCount != 1 {
				return nil, errors.New("CONNECT requires exactly one Host")
			}
			return request, nil
		}
	}
	return nil, errors.New("CONNECT header exceeds limit")
}

func connectHost(request *http.Request) (string, error) {
	if request.Method != http.MethodConnect || request.Proto != "HTTP/1.1" ||
		request.Host != request.RequestURI || request.URL.Host != request.RequestURI ||
		request.URL.Scheme != "" || request.URL.User != nil || request.URL.Path != "" ||
		request.URL.RawQuery != "" || request.URL.Fragment != "" ||
		request.ContentLength != 0 || len(request.TransferEncoding) != 0 ||
		len(request.Header.Values("Content-Length")) != 0 || len(request.Header.Values("Transfer-Encoding")) != 0 {
		return "", errors.New("CONNECT requires a bodyless DNS authority")
	}
	host, port, err := net.SplitHostPort(request.RequestURI)
	if err != nil || port != "443" || len(host) > 253 || net.ParseIP(host) != nil || !strings.Contains(host, ".") {
		return "", errors.New("CONNECT requires a DNS host on port 443")
	}
	host = strings.ToLower(host)
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid CONNECT DNS host")
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", errors.New("invalid CONNECT DNS host")
			}
		}
	}
	return host, nil
}

func reject(conn net.Conn, status int) error {
	_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
	challenge := ""
	if status == http.StatusProxyAuthRequired {
		challenge = "Proxy-Authenticate: Basic realm=\"FlClash local inspection\"\r\n"
	}
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\n%sContent-Length: 0\r\nConnection: close\r\n\r\n", status, http.StatusText(status), challenge)
	return errors.New("inspection CONNECT rejected")
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (r *Runtime) exchange(ctx context.Context, conn net.Conn) error {
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()
	_ = conn.SetDeadline(time.Now().Add(HandshakeTimeout))
	reader := bufio.NewReaderSize(conn, MaxConnectHeader)
	request, err := readConnect(reader)
	if err != nil {
		return reject(conn, http.StatusBadRequest)
	}
	defer request.Body.Close()
	values := request.Header.Values("Proxy-Authorization")
	if len(values) != 1 || len(values[0]) > 256 {
		return reject(conn, http.StatusProxyAuthRequired)
	}
	provided := sha256.Sum256([]byte(values[0]))
	if subtle.ConstantTimeCompare(provided[:], r.authHash[:]) != 1 {
		return reject(conn, http.StatusProxyAuthRequired)
	}
	host, err := connectHost(request)
	if err != nil {
		return reject(conn, http.StatusBadRequest)
	}
	if err := r.config.Authorize(ctx, host); err != nil || ctx.Err() != nil {
		return reject(conn, http.StatusForbidden)
	}
	rawUpstream, err := r.config.Dial(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		return reject(conn, http.StatusBadGateway)
	}
	defer rawUpstream.Close()
	stopUpstream := context.AfterFunc(ctx, func() { _ = rawUpstream.Close() })
	defer stopUpstream()
	upstream := tls.Client(rawUpstream, &tls.Config{
		ServerName: host, RootCAs: r.config.Roots, MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"}, SessionTicketsDisabled: true,
	})
	handshakeCtx, cancelHandshake := context.WithTimeout(ctx, HandshakeTimeout)
	err = upstream.HandshakeContext(handshakeCtx)
	cancelHandshake()
	if err != nil {
		return reject(conn, http.StatusBadGateway)
	}
	peer := upstream.ConnectionState()
	if len(peer.VerifiedChains) == 0 || (peer.NegotiatedProtocol != "" && peer.NegotiatedProtocol != "http/1.1") {
		return reject(conn, http.StatusBadGateway)
	}
	leaf, err := r.config.Leaf(ctx, host)
	if err != nil || leaf == nil || ctx.Err() != nil {
		return reject(conn, http.StatusForbidden)
	}
	_ = conn.SetDeadline(time.Now().Add(HandshakeTimeout))
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return err
	}
	downstream := tls.Server(&bufferedConn{Conn: conn, reader: reader}, &tls.Config{
		Certificates: []tls.Certificate{*leaf}, MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"}, SessionTicketsDisabled: true,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if strings.ToLower(hello.ServerName) != host || ctx.Err() != nil {
				return nil, errors.New("inspection SNI does not match CONNECT host")
			}
			if len(hello.SupportedProtos) != 0 {
				found := false
				for _, protocol := range hello.SupportedProtos {
					found = found || protocol == "http/1.1"
				}
				if !found {
					return nil, errors.New("inspection runtime supports HTTP/1.1 only")
				}
			}
			return nil, r.config.Authorize(ctx, host)
		},
	})
	handshakeCtx, cancelHandshake = context.WithTimeout(ctx, HandshakeTimeout)
	err = downstream.HandshakeContext(handshakeCtx)
	cancelHandshake()
	if err != nil {
		return errors.New("inspection client handshake failed")
	}
	if err := r.config.Authorize(ctx, host); err != nil || ctx.Err() != nil {
		return errors.New("inspection authorization revoked")
	}
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	_ = rawUpstream.SetDeadline(deadline)
	return r.relay(ctx, downstream, upstream, conn, rawUpstream)
}

func (r *Runtime) relay(ctx context.Context, client, upstream *tls.Conn, rawClient, rawUpstream net.Conn) error {
	type copied struct {
		upload bool
		n      int64
		err    error
	}
	results := make(chan copied, 2)
	copyOne := func(dst, src *tls.Conn, upload bool) {
		result := copied{upload: upload}
		defer func() {
			if recover() != nil {
				result.err = errors.New("inspection relay failed")
			}
			results <- result
		}()
		result.n, result.err = io.CopyBuffer(dst, src, make([]byte, 16*1024))
	}
	go copyOne(upstream, client, true)
	go copyOne(client, upstream, false)
	first := <-results
	var second copied
	if first.upload && first.err == nil {
		_ = upstream.CloseWrite()
		second = <-results
		_ = rawClient.Close()
		_ = rawUpstream.Close()
	} else {
		_ = rawClient.Close()
		_ = rawUpstream.Close()
		second = <-results
	}
	r.mu.Lock()
	for _, result := range []copied{first, second} {
		if result.upload {
			r.uploaded += uint64(result.n)
		} else {
			r.downloaded += uint64(result.n)
		}
	}
	r.mu.Unlock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return first.err
}
