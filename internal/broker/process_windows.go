//go:build windows

package broker

import (
	"errors"
	"time"
)

var errBrokerUnsupported = errors.New("broker: the Broker process is not supported on Windows yet")

// DefaultIdleTimeout mirrors the unix build for callers that reference it
// regardless of platform (e.g. the unlock command's flag default).
const DefaultIdleTimeout = 4 * time.Hour

func SocketPath() (string, error) { return "", errBrokerUnsupported }

func RequestKey() ([]byte, error) { return nil, ErrLocked }

func StopBroker() error { return nil }

func StartBroker(key []byte, timeout time.Duration) error { return errBrokerUnsupported }

func Serve(socketPath string, key []byte, timeout time.Duration) error { return errBrokerUnsupported }
