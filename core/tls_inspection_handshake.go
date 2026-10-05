package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"time"
)

const tlsInspectionHandshakeTimeout = 3 * time.Second

func verifyTLSInspectionLeafHandshake(ctx context.Context, entry *tlsInspectionLeafEntry, authority *x509.Certificate) error {
	if entry == nil || entry.Certificate == nil || entry.PrivateKey == nil || authority == nil {
		return errors.New("local TLS verification requires validated signing material")
	}
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		if err := verifyTLSInspectionHandshakeVersion(ctx, entry, authority, version); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func verifyTLSInspectionHandshakeVersion(ctx context.Context, entry *tlsInspectionLeafEntry, authority *x509.Certificate, version uint16) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = clientRaw.Close()
		_ = serverRaw.Close()
	})
	defer stopCancellation()
	if deadline, ok := ctx.Deadline(); ok {
		_ = clientRaw.SetDeadline(deadline)
		_ = serverRaw.SetDeadline(deadline)
	}
	roots := x509.NewCertPool()
	roots.AddCert(authority)
	client := tls.Client(clientRaw, &tls.Config{
		RootCAs:                roots,
		ServerName:             entry.Metadata.Host,
		MinVersion:             version,
		MaxVersion:             version,
		NextProtos:             []string{"http/1.1"},
		SessionTicketsDisabled: true,
	})
	server := tls.Server(serverRaw, &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{entry.Certificate.Raw},
			PrivateKey:  entry.PrivateKey,
			Leaf:        entry.Certificate,
		}},
		MinVersion:             version,
		MaxVersion:             version,
		NextProtos:             []string{"http/1.1"},
		SessionTicketsDisabled: true,
	})
	var challenge [32]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		return errors.New("local TLS challenge generation failed")
	}
	serverDone := make(chan error, 1)
	go func() {
		var result error
		defer func() {
			if recover() != nil {
				result = errors.New("local TLS server verification failed")
			}
			serverDone <- result
		}()
		result = exchangeTLSInspectionChallenge(ctx, server, challenge[:])
	}()
	clientErr := client.HandshakeContext(ctx)
	if clientErr == nil {
		state := client.ConnectionState()
		if !state.HandshakeComplete || state.Version != version || state.NegotiatedProtocol != "http/1.1" || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) != 1 || !bytes.Equal(state.PeerCertificates[0].Raw, entry.Certificate.Raw) {
			clientErr = errors.New("local TLS negotiation did not match the requested contract")
		}
	}
	if clientErr == nil {
		var sent int
		sent, clientErr = client.Write(challenge[:])
		if clientErr == nil && sent != len(challenge) {
			clientErr = io.ErrShortWrite
		}
	}
	if clientErr == nil {
		var received [32]byte
		_, clientErr = io.ReadFull(client, received[:])
		if clientErr == nil && !bytes.Equal(received[:], challenge[:]) {
			clientErr = errors.New("local TLS challenge did not round-trip")
		}
	}
	_ = clientRaw.Close()
	_ = serverRaw.Close()
	serverErr := <-serverDone
	if err := ctx.Err(); err != nil {
		return err
	}
	if clientErr != nil {
		return clientErr
	}
	return serverErr
}

func exchangeTLSInspectionChallenge(ctx context.Context, server *tls.Conn, challenge []byte) error {
	if err := server.HandshakeContext(ctx); err != nil {
		return err
	}
	var received [32]byte
	if _, err := io.ReadFull(server, received[:]); err != nil {
		return err
	}
	if !bytes.Equal(received[:], challenge) {
		return errors.New("local TLS challenge mismatch")
	}
	n, err := server.Write(received[:])
	if err == nil && n != len(received) {
		return io.ErrShortWrite
	}
	return err
}

func completeTLSInspectionLeafPreparation(entry *tlsInspectionLeafEntry, cacheHit bool, authority *x509.Certificate, verifyHandshake bool) (*TLSInspectionLeafCertificateStatus, *MethodError) {
	result := tlsInspectionLeafCertificateStatus(entry, cacheHit)
	if !verifyHandshake {
		return result, nil
	}
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), tlsInspectionHandshakeTimeout)
	defer cancel()
	if err := verifyTLSInspectionLeafHandshake(ctx, entry, authority); err != nil {
		resetTLSInspectionLeafPolicySession()
		return nil, &MethodError{
			Code:    "leaf_handshake_failed",
			Message: "The local TLS handshake self-test failed; inspection authorization was revoked",
		}
	}
	result.HandshakeVerified = true
	result.HandshakeVersions = []string{"TLS 1.2", "TLS 1.3"}
	result.HandshakeALPN = "http/1.1"
	result.HandshakeScope = "in-memory-only"
	result.HandshakeDurationMs = time.Since(started).Milliseconds()
	return result, nil
}
