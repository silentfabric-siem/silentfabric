package ingest

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/silentfabric-siem/silentfabric/internal/event"
)

const (
	maxSyslogMessage = 64 * 1024
	tcpIdleTimeout   = 10 * time.Minute
)

// ListenSyslogTCP accepts syslog over TCP with either newline-delimited or
// octet-counted framing (RFC 6587), detected per message.
func ListenSyslogTCP(ctx context.Context, addr string, out chan<- event.Event) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	slog.Info("syslog listening", "proto", "tcp", "addr", ln.Addr().String())

	var wg sync.WaitGroup
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	defer wg.Wait()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			handleSyslogConn(ctx, conn, out)
		}()
	}
}

func handleSyslogConn(ctx context.Context, conn net.Conn, out chan<- event.Event) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	peer, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	r := bufio.NewReaderSize(conn, maxSyslogMessage)
	for {
		conn.SetReadDeadline(time.Now().Add(tcpIdleTimeout))
		line, err := readFrame(r)
		if line != "" {
			ev := ParseSyslog(line, time.Now().UTC())
			ev.Fields["log.source.ip"] = peer
			if ev.Host == "" {
				ev.Host = peer
			}
			select {
			case out <- ev:
			case <-ctx.Done():
				return
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) && ctx.Err() == nil {
				slog.Debug("syslog tcp connection closed", "peer", peer, "err", err)
			}
			return
		}
	}
}

// readFrame reads one message. A frame that starts with a digit is
// octet-counted ("LEN SP MSG"); anything else ends at a newline.
func readFrame(r *bufio.Reader) (string, error) {
	for {
		b, err := r.Peek(1)
		if err != nil {
			return "", err
		}
		if b[0] != '\n' && b[0] != '\r' {
			break
		}
		r.ReadByte()
	}
	b, _ := r.Peek(1)
	if b[0] >= '1' && b[0] <= '9' {
		lenStr, err := r.ReadString(' ')
		if err != nil {
			return "", err
		}
		n, err := strconv.Atoi(strings.TrimSpace(lenStr))
		if err != nil || n > maxSyslogMessage {
			return "", fmt.Errorf("bad octet count %q", lenStr)
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return string(buf), nil
	}

	line, err := r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		// Oversized line: keep the first 64 KiB and discard the rest.
		kept := string(line)
		for errors.Is(err, bufio.ErrBufferFull) {
			_, err = r.ReadSlice('\n')
		}
		return kept, err
	}
	return strings.TrimRight(string(line), "\r\n"), err
}
