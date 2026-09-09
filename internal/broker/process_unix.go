//go:build !windows

// This file implements the Broker process itself (see Serve, started by
// cpass broker-serve) and the client/control calls cpass unlock, cpass lock
// and UnlockKey use to reach it (StartBroker, StopBroker, RequestKey).
package broker

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"claudepass/internal/vault"
)

const socketFileName = "cpass.sock"

// maxSocketPathLen leaves margin under sizeof(sockaddr_un.sun_path) - 1:
// 104 bytes on darwin/BSD, 108 on Linux. A path this long would fail at
// bind(2)/connect(2) with a cryptic "invalid argument".
const maxSocketPathLen = 100

// dialTimeout bounds how long a client waits for the Broker to answer.
const dialTimeout = 2 * time.Second

// DefaultIdleTimeout is how long the Broker holds the key with no requests
// before dropping it, absent --timeout.
const DefaultIdleTimeout = 4 * time.Hour

// SocketPath is where the Broker process listens: under $XDG_RUNTIME_DIR
// (the ssh-agent convention) when set, else under CPASS_HOME.
func SocketPath() (string, error) {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		h, err := Home()
		if err != nil {
			return "", err
		}
		dir = h
	}
	p := filepath.Join(dir, socketFileName)
	if len(p) > maxSocketPathLen {
		return "", fmt.Errorf("broker: socket path %q is too long for a unix socket; set XDG_RUNTIME_DIR to a shorter directory", p)
	}
	return p, nil
}

// RequestKey asks a running Broker process for the key it holds. It returns
// ErrLocked if none is running (nothing listening on the socket) or if the
// exchange fails for any reason — from the caller's perspective those are
// both simply "locked".
func RequestKey() ([]byte, error) {
	path, err := SocketPath()
	if err != nil {
		return nil, err
	}
	conn, err := net.DialTimeout("unix", path, dialTimeout)
	if err != nil {
		return nil, ErrLocked
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(dialTimeout))
	if _, err := conn.Write([]byte("RESOLVE\n")); err != nil {
		return nil, ErrLocked
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return nil, ErrLocked
	}
	enc, ok := strings.CutPrefix(strings.TrimSpace(line), "KEY ")
	if !ok {
		return nil, ErrLocked
	}
	key, err := base64.StdEncoding.DecodeString(enc)
	if err != nil || len(key) != vault.KeySize {
		return nil, ErrLocked
	}
	return key, nil
}

// StopBroker tells a running Broker process to drop its key and exit. It is
// not an error if none is running: cpass lock is idempotent.
func StopBroker() error {
	path, err := SocketPath()
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("unix", path, dialTimeout)
	if err != nil {
		os.Remove(path) // clear a stale socket file left by a killed Broker
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(dialTimeout))
	conn.Write([]byte("LOCK\n"))
	bufio.NewReader(conn).ReadString('\n') // wait for the ack; its content doesn't matter
	return nil
}

// StartBroker starts a Broker process holding key on the socket, replacing
// any Broker already running there, and waits until it is ready to serve
// before returning. The key is handed to the child over a pipe, never on
// its command line, so it cannot appear in a process listing.
func StartBroker(key []byte, timeout time.Duration) error {
	path, err := SocketPath()
	if err != nil {
		return err
	}
	if err := StopBroker(); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("broker: cannot find the cpass binary: %w", err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, "broker-serve", "-socket", path, "-timeout", timeout.String())
	cmd.Stdin = r
	cmd.Env = os.Environ()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		r.Close()
		w.Close()
		return fmt.Errorf("broker: start: %w", err)
	}
	r.Close()
	_, werr := w.Write([]byte(base64.StdEncoding.EncodeToString(key) + "\n"))
	w.Close()
	if werr != nil {
		return fmt.Errorf("broker: hand off key: %w", werr)
	}
	_ = cmd.Process.Release() // detach: it outlives this process, nothing to Wait for

	deadline := time.Now().Add(dialTimeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("unix", path, 100*time.Millisecond)
		if err == nil {
			c.Close()
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return errors.New("broker: process did not start listening in time")
}

// Serve runs the Broker process itself: listens on socketPath, holds key in
// memory, and answers RESOLVE/LOCK requests until told to stop (LOCK) or
// idle for timeout with no requests. Started by StartBroker via
// cpass broker-serve; not for direct use.
func Serve(socketPath string, key []byte, timeout time.Duration) error {
	os.Remove(socketPath) // clear a stale socket left by a crashed Broker
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		return err
	}
	addr, err := net.ResolveUnixAddr("unix", socketPath)
	if err != nil {
		return err
	}
	l, err := net.ListenUnix("unix", addr)
	if err != nil {
		return fmt.Errorf("broker: listen on %s: %w", socketPath, err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		l.Close()
		os.Remove(socketPath)
		return err
	}
	defer func() {
		l.Close()
		os.Remove(socketPath)
	}()
	for {
		if err := l.SetDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
		conn, err := l.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return nil // idle timeout: drop the key by exiting
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		stop := serveConn(conn, key)
		conn.Close()
		if stop {
			return nil
		}
	}
}

func serveConn(conn net.Conn, key []byte) (stop bool) {
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return false
	}
	switch strings.TrimSpace(line) {
	case "RESOLVE":
		fmt.Fprintf(conn, "KEY %s\n", base64.StdEncoding.EncodeToString(key))
	case "LOCK":
		fmt.Fprintln(conn, "OK")
		return true
	default:
		fmt.Fprintln(conn, "ERR unknown command")
	}
	return false
}
