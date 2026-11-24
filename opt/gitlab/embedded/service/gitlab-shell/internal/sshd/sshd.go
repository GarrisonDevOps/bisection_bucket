// Package sshd provides functionality for handling SSH connections
package sshd

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
	"golang.org/x/crypto/ssh"

	"gitlab.com/gitlab-org/gitlab-shell/v14/client"
	"gitlab.com/gitlab-org/gitlab-shell/v14/internal/command"
	"gitlab.com/gitlab-org/gitlab-shell/v14/internal/command/commandargs"
	"gitlab.com/gitlab-org/gitlab-shell/v14/internal/config"
	"gitlab.com/gitlab-org/gitlab-shell/v14/internal/gitlabnet"
	"gitlab.com/gitlab-org/gitlab-shell/v14/internal/metrics"

	"gitlab.com/gitlab-org/labkit/correlation"
	"gitlab.com/gitlab-org/labkit/v2/fields"
	"gitlab.com/gitlab-org/labkit/v2/log"
)

func init() {
	// nginx OSS stream re-encodes upstream PROXY v2 as v1 with plain IPv4 in TCP6 lines when address families differ,
	// e.g. GitLab Dedicated behind Cloudflare Spectrum. go-proxyproto v0.15.0 rejects these by default.
	// This does not widen trust. Plain IPv4 parses to the same IPv4-mapped value as ::ffff: notation;
	// proxy_allowed / proxy_policy control header trust.
	// https://github.com/pires/go-proxyproto/pull/167
	// https://gitlab.com/gitlab-org/gitlab-shell/-/merge_requests/1430
	// This process-wide switch must be set once at init and never changed at runtime.
	proxyproto.V1AcceptIPv4InTCP6 = true
}

type status int

const (
	// StatusStarting represents the starting status of the SSH server
	StatusStarting status = iota

	// StatusReady represents the ready status of the SSH server
	StatusReady

	// StatusOnShutdown represents the status when the SSH server is shutting down
	StatusOnShutdown

	// StatusClosed represents the closed status of the SSH server
	StatusClosed
)

const (
	proxyPolicyRequire = "require"
	proxyPolicyIgnore  = "ignore"
	proxyPolicyReject  = "reject"
)

// Server represents an SSH server instance
type Server struct {
	Config *config.Config

	status       status
	statusMu     sync.RWMutex
	wg           sync.WaitGroup
	listener     net.Listener
	serverConfig *serverConfig
}

// NewServer creates a new instance of Server
func NewServer(cfg *config.Config) (*Server, error) {
	serverConfig, err := newServerConfig(cfg)
	if err != nil {
		return nil, err
	}

	return &Server{Config: cfg, serverConfig: serverConfig}, nil
}

// ListenAndServe starts listening for SSH connections and serves them
func (s *Server) ListenAndServe(ctx context.Context) error {
	if err := s.listen(ctx); err != nil {
		return err
	}
	defer func() { _ = s.listener.Close() }()

	s.serve(ctx)

	return nil
}

// Shutdown gracefully shuts down the SSH server
func (s *Server) Shutdown() error {
	if s.listener == nil {
		return nil
	}

	s.changeStatus(StatusOnShutdown)

	return s.listener.Close()
}

// Addr returns the listener's network address, or an empty string if not yet listening.
func (s *Server) Addr() string {
	s.statusMu.RLock()
	defer s.statusMu.RUnlock()

	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// MonitoringServeMux returns the ServeMux for monitoring endpoints
func (s *Server) MonitoringServeMux() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc(s.Config.Server.ReadinessProbe, func(w http.ResponseWriter, _ *http.Request) {
		if s.getStatus() == StatusReady {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	})

	mux.HandleFunc(s.Config.Server.LivenessProbe, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	return mux
}

func (s *Server) listen(ctx context.Context) error {
	sshListener, err := net.Listen("tcp", s.Config.Server.Listen)
	if err != nil {
		return fmt.Errorf("failed to listen for connection: %w", err)
	}

	if s.Config.Server.ProxyProtocol {
		policy, err := s.proxyPolicy()
		if err != nil {
			return fmt.Errorf("invalid policy configuration: %w", err)
		}

		sshListener = &proxyproto.Listener{
			Listener:          sshListener,
			ConnPolicy:        policy,
			ReadHeaderTimeout: time.Duration(s.Config.Server.ProxyHeaderTimeout),
		}

		ctx = log.AppendFields(ctx, log.TCPAddress(sshListener.Addr().String()))
		log.FromContext(ctx).InfoContext(ctx, "Proxy protocol is enabled")
	}

	if len(s.serverConfig.cfg.Server.PublicKeyAlgorithms) > 0 {
		ctx = log.AppendFields(ctx, slog.Any("supported_public_key_algorithms", s.serverConfig.cfg.Server.PublicKeyAlgorithms))
	}

	log.FromContext(ctx).InfoContext(ctx, "Listening for SSH connections")

	s.listener = sshListener

	return nil
}

func (s *Server) serve(ctx context.Context) {
	s.changeStatus(StatusReady)

	for {
		nconn, err := s.listener.Accept()
		if err != nil {
			if s.getStatus() == StatusOnShutdown {
				break
			}

			log.FromContext(ctx).WarnContext(ctx, "Failed to accept connection", log.ErrorMessage(err.Error()))
			continue
		}

		s.wg.Add(1)
		go s.handleConn(ctx, nconn)
	}

	s.wg.Wait()

	s.changeStatus(StatusClosed)
}

func (s *Server) changeStatus(st status) {
	s.statusMu.Lock()
	s.status = st
	s.statusMu.Unlock()
}

func (s *Server) getStatus() status {
	s.statusMu.RLock()
	defer s.statusMu.RUnlock()

	return s.status
}

func contextWithValues(parent context.Context, nconn net.Conn) context.Context {
	correlationID := correlation.SafeRandomID()
	ctx := correlation.ContextWithCorrelation(parent, correlationID)
	// Seed a logger carrying the per-connection correlation_id so log lines
	// emitted during this connection stay in sync with the value outbound HTTP
	// requests propagate via X-Request-Id. Without this step the logger
	// inherits the parent/process correlation_id and the two diverge.
	ctx = log.WithLogger(ctx, slog.Default().With(slog.String(fields.CorrelationID, correlationID)))

	// If we're dealing with a PROXY connection, register the original requester's IP
	mconn, ok := nconn.(*proxyproto.Conn)
	if ok {
		ip := gitlabnet.ParseIP(mconn.Raw().RemoteAddr().String())
		ctx = context.WithValue(ctx, client.OriginalRemoteIPContextKey{}, ip)
	}

	return ctx
}

func (s *Server) handleConn(ctx context.Context, nconn net.Conn) {
	defer s.wg.Done()

	metrics.SshdConnectionsInFlight.Inc()
	defer metrics.SshdConnectionsInFlight.Dec()

	ctx, cancel := context.WithCancel(contextWithValues(ctx, nconn))
	defer cancel()
	remoteAddr := nconn.RemoteAddr().String()
	ctx = log.AppendFields(ctx, slog.String("remote_addr", remoteAddr))

	go func() {
		<-ctx.Done()
		_ = nconn.Close() // Close the connection when context is canceled
	}()

	// Prevent a panic in a single connection from taking out the whole server
	defer func() {
		if err := recover(); err != nil {
			log.FromContext(ctx).ErrorContext(ctx, "panic handling session", slog.Any("recovered_error", err))
			metrics.SliSshdSessionsErrorsTotal.Inc()
		}
	}()

	started := time.Now()
	conn := newConnection(s.Config, nconn)

	// The sessions of one connection run in goroutines of their own, several
	// at a time, so each stores its command.LogData here atomically when it
	// ends, and the "access: finish" line logs the last one stored.
	var lastLogData atomic.Value

	conn.handle(ctx, s.serverConfig.get(ctx, &conn.outcome), func(ctx context.Context, sconn *ssh.ServerConn, channel ssh.Channel, requests <-chan *ssh.Request) error {
		session := &session{
			cfg:                 s.Config,
			channel:             channel,
			gitlabKeyID:         sconn.Permissions.Extensions["key-id"],
			gitlabKrb5Principal: sconn.Permissions.Extensions["krb5principal"],
			gitlabUsername:      sconn.Permissions.Extensions[certPermUsername],
			namespace:           sconn.Permissions.Extensions[certPermNamespace],
			remoteAddr:          remoteAddr,
			started:             time.Now(),
		}
		if ext := sconn.Permissions.Extensions; ext[certPermTrustSource] != "" {
			session.certificate = &commandargs.CertificateMetadata{
				CAFingerprint: ext[certPermCAFingerprint],
				Identity:      ext[certPermIdentity],
				TrustSource:   ext[certPermTrustSource],
			}
		}

		ctxWithLogData, err := session.handle(ctx, requests)
		lastLogData.Store(extractLogDataFromContext(ctxWithLogData))

		return err
	})

	logData, _ := lastLogData.Load().(command.LogData)
	log.FromContext(ctx).InfoContext(ctx, "access: finish",
		log.DurationS(time.Since(started)),
		log.GitLabUserName(logData.Username),
		slog.Int64("written_bytes", logData.WrittenBytes),
		slog.Any("meta", logData.Meta),
	)
}

func (s *Server) proxyPolicy() (proxyproto.ConnPolicyFunc, error) {
	if len(s.Config.Server.ProxyAllowed) > 0 {
		return proxyproto.PolicyFromRanges(s.Config.Server.ProxyAllowed, proxyproto.USE, proxyproto.REJECT)
	}

	// Set the Policy value based on config
	// Values are taken from https://github.com/pires/go-proxyproto/blob/195fedcfbfc1be163f3a0d507fac1709e9d81fed/policy.go#L20
	switch strings.ToLower(s.Config.Server.ProxyPolicy) {
	case proxyPolicyRequire:
		return staticProxyPolicy(proxyproto.REQUIRE), nil
	case proxyPolicyIgnore:
		return staticProxyPolicy(proxyproto.IGNORE), nil
	case proxyPolicyReject:
		return staticProxyPolicy(proxyproto.REJECT), nil
	default:
		return staticProxyPolicy(proxyproto.USE), nil
	}
}

func extractLogDataFromContext(ctx context.Context) command.LogData {
	logData := command.LogData{}

	if ctx == nil {
		return logData
	}

	if ctx.Value(command.LogDataKey) != nil {
		logData = ctx.Value(command.LogDataKey).(command.LogData)
	}

	return logData
}

func staticProxyPolicy(policy proxyproto.Policy) proxyproto.ConnPolicyFunc {
	return func(_ proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
		return policy, nil
	}
}
