from pathlib import Path
import shutil
import subprocess

from http2_batch_common import ROOT, patch_all as patch_core
from http2_batch_http1 import patch_all as patch_http1
from http2_batch_tests import write_tests


def add_http1_watcher_compatibility() -> None:
    runtime_path = ROOT / "core/inspectionruntime/runtime.go"
    text = runtime_path.read_text()
    marker = "func (r *Runtime) relay(\n"
    compatibility = '''func (r *Runtime) watchHTTP1Timeline(
\tctx context.Context,
\tobservation *runtimeObservation,
\ttimeline *http1MetadataTimeline,
\tsignal <-chan struct{},
\tdone <-chan struct{},
) {
\tr.watchHTTPTimeline(ctx, observation, timeline, signal, done)
}

'''
    if marker not in text:
        raise RuntimeError("relay marker missing for HTTP/1 watcher compatibility")
    runtime_path.write_text(text.replace(marker, compatibility + marker, 1))


def restore_verified_upstream_gate() -> None:
    runtime_path = ROOT / "core/inspectionruntime/runtime.go"
    text = runtime_path.read_text()
    start = text.index("\tobservation = r.beginObservation(host)\n")
    end_marker = '''\tuploaded, downloaded, failure = r.relay(
\t\tctx, downstream, upstream, conn, rawUpstream, protocol, observation,
\t)
\treturn failure
'''
    end = text.index(end_marker, start) + len(end_marker)
    exchange = '''\tobservation = r.beginObservation(host)
\tfailureKind = "upstream-dial"
\trawUpstream, err := r.config.Dial(ctx, "tcp", net.JoinHostPort(host, "443"))
\tif err != nil {
\t\tfailure = reject(conn, http.StatusBadGateway)
\t\treturn failure
\t}
\tdefer rawUpstream.Close()
\tstopUpstream := context.AfterFunc(ctx, func() { _ = rawUpstream.Close() })
\tdefer stopUpstream()
\tr.updateObservation(observation, func(value *Observation) {
\t\tvalue.UpstreamDialCompletedAfterMilliseconds = elapsedMilliseconds(value.StartedAt)
\t})
\tupstream := tls.Client(rawUpstream, &tls.Config{
\t\tServerName: host, RootCAs: r.config.Roots, MinVersion: tls.VersionTLS12,
\t\tNextProtos: []string{"h2", "http/1.1"}, SessionTicketsDisabled: true,
\t})
\tfailureKind = "upstream-tls"
\t_ = rawUpstream.SetDeadline(time.Now().Add(HandshakeTimeout))
\thandshakeCtx, cancelHandshake := context.WithTimeout(ctx, HandshakeTimeout)
\terr = upstream.HandshakeContext(handshakeCtx)
\tcancelHandshake()
\t_ = rawUpstream.SetDeadline(time.Time{})
\tif err != nil {
\t\tfailure = reject(conn, http.StatusBadGateway)
\t\treturn failure
\t}
\tpeer := upstream.ConnectionState()
\tprotocol := peer.NegotiatedProtocol
\tif protocol == "" {
\t\tprotocol = "http/1.1"
\t}
\tif len(peer.VerifiedChains) == 0 ||
\t\t(protocol != "http/1.1" && protocol != "h2") {
\t\tfailure = reject(conn, http.StatusBadGateway)
\t\treturn failure
\t}
\tr.updateObservation(observation, func(value *Observation) {
\t\tvalue.UpstreamTLSVersion = tlsVersionName(peer.Version)
\t\tvalue.UpstreamTLSCompletedAfterMilliseconds = elapsedMilliseconds(value.StartedAt)
\t\tvalue.ALPN = protocol
\t})
\tfailureKind = "leaf"
\tleaf, err := r.config.Leaf(ctx, host)
\tif err != nil || leaf == nil || ctx.Err() != nil {
\t\tfailure = reject(conn, http.StatusForbidden)
\t\treturn failure
\t}
\t_ = conn.SetDeadline(time.Now().Add(HandshakeTimeout))
\tif _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\\r\\n\\r\\n"); err != nil {
\t\tfailure = err
\t\treturn failure
\t}
\tdownstream := tls.Server(&bufferedConn{Conn: conn, reader: reader}, &tls.Config{
\t\tCertificates: []tls.Certificate{*leaf}, MinVersion: tls.VersionTLS12,
\t\tNextProtos: []string{protocol}, SessionTicketsDisabled: true,
\t\tGetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
\t\t\tif strings.ToLower(hello.ServerName) != host || ctx.Err() != nil {
\t\t\t\treturn nil, errors.New("inspection SNI does not match CONNECT host")
\t\t\t}
\t\t\tif len(hello.SupportedProtos) == 0 {
\t\t\t\tif protocol == "h2" {
\t\t\t\t\treturn nil, errors.New("inspection client did not advertise negotiated HTTP/2")
\t\t\t\t}
\t\t\t} else {
\t\t\t\tfound := false
\t\t\t\tfor _, candidate := range hello.SupportedProtos {
\t\t\t\t\tfound = found || candidate == protocol
\t\t\t\t}
\t\t\t\tif !found {
\t\t\t\t\treturn nil, errors.New("inspection client and upstream ALPN do not match")
\t\t\t\t}
\t\t\t}
\t\t\treturn nil, r.config.Authorize(ctx, host)
\t\t},
\t})
\tfailureKind = "downstream-tls"
\thandshakeCtx, cancelHandshake = context.WithTimeout(ctx, HandshakeTimeout)
\terr = downstream.HandshakeContext(handshakeCtx)
\tcancelHandshake()
\tif err != nil {
\t\tfailure = errors.New("inspection client handshake failed")
\t\treturn failure
\t}
\tdownstreamState := downstream.ConnectionState()
\tdownstreamProtocol := downstreamState.NegotiatedProtocol
\tif downstreamProtocol == "" {
\t\tdownstreamProtocol = "http/1.1"
\t}
\tif downstreamProtocol != protocol {
\t\tfailure = errors.New("inspection client and upstream protocol mismatch")
\t\treturn failure
\t}
\tr.updateObservation(observation, func(value *Observation) {
\t\tvalue.DownstreamTLSVersion = tlsVersionName(downstreamState.Version)
\t\tvalue.DownstreamTLSCompletedAfterMilliseconds = elapsedMilliseconds(value.StartedAt)
\t})
\tfailureKind = "authorization-revoked"
\tif err := r.config.Authorize(ctx, host); err != nil || ctx.Err() != nil {
\t\tfailure = errors.New("inspection authorization revoked")
\t\treturn failure
\t}
\tdeadline, _ := ctx.Deadline()
\t_ = conn.SetDeadline(deadline)
\t_ = rawUpstream.SetDeadline(deadline)
\tfailureKind = "relay"
\tuploaded, downloaded, failure = r.relay(
\t\tctx, downstream, upstream, conn, rawUpstream, protocol, observation,
\t)
\treturn failure
'''
    runtime_path.write_text(text[:start] + exchange + text[end:])


def main() -> None:
    patch_core()
    restore_verified_upstream_gate()
    patch_http1()
    add_http1_watcher_compatibility()
    write_tests()

    # Keep the JSON test payload valid while the generator itself remains a
    # raw Python string that is easy to review.
    test_path = ROOT / "core/inspectionruntime/http2_timeline_test.go"
    test_path.write_text(
        test_path.read_text().replace(r'`{\"ok\":true}`', '`{"ok":true}`')
    )

    go_files = [
        "core/http_observer.go",
        "core/tls_inspection_runtime.go",
        "core/inspectionruntime/capture_policy.go",
        "core/inspectionruntime/capture_policy_test.go",
        "core/inspectionruntime/http1_metadata.go",
        "core/inspectionruntime/http1_timeline.go",
        "core/inspectionruntime/http2_headers.go",
        "core/inspectionruntime/http2_timeline.go",
        "core/inspectionruntime/http2_timeline_test.go",
        "core/inspectionruntime/runtime.go",
    ]
    subprocess.run(["gofmt", "-w", *go_files], cwd=ROOT, check=True)

    # The workflow and patch helpers are deliberately one-shot and must not
    # remain in the product branch after the generated changes pass tests.
    for helper in (
        ROOT / "tools/http2_batch_common.py",
        ROOT / "tools/http2_batch_http1.py",
        ROOT / "tools/http2_batch_tests.py",
    ):
        helper.unlink(missing_ok=True)
    shutil.rmtree(ROOT / "tools/__pycache__", ignore_errors=True)


if __name__ == "__main__":
    main()
