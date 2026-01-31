package lib

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/cr4n5/liteproxy/config"
	"github.com/quic-go/quic-go"
	log "github.com/sirupsen/logrus"
)

type UDPSession struct {
	mu       sync.RWMutex
	creating sync.Map
	ln       net.PacketConn
	session  map[string]*quic.Stream
	ping     map[string]chan struct{}
}

func NewUDPSession(ln net.PacketConn) *UDPSession {
	return &UDPSession{
		ln:      ln,
		session: make(map[string]*quic.Stream),
		ping:    make(map[string]chan struct{}),
	}
}

func (u *UDPSession) GetOrCreateStream(ctx context.Context, route config.RouteConfig, bridgeConn *quic.Conn, addr net.Addr) (*quic.Stream, error) {
	// creating sync.Map to prevent duplicate creations
	actual, _ := u.creating.LoadOrStore(addr.String(), &sync.Mutex{})
	mu := actual.(*sync.Mutex)

	mu.Lock()
	defer func() {
		mu.Unlock()
		u.creating.Delete(addr.String())
	}()

	stream, ok := u.GetStream(addr)
	if ok {
		return stream, nil
	}
	stream, err := HandConnToTarget(ctx, &route, bridgeConn)
	if err != nil {
		return nil, err
	}
	u.SetStream(addr, stream)

	return stream, nil
}

func (u *UDPSession) GetStream(addr net.Addr) (*quic.Stream, bool) {
	u.mu.RLock()
	stream, ok := u.session[addr.String()]
	u.mu.RUnlock()
	if ok {
		// Reset timeout timer
		select {
		case u.ping[addr.String()] <- struct{}{}:
		default:
		}
	}
	return stream, ok
}

func (u *UDPSession) SetStream(addr net.Addr, stream *quic.Stream) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.session[addr.String()] = stream
	u.ping[addr.String()] = make(chan struct{}, 1)
	log.Infof("UDP stream created for %s", addr.String())
	go u.TimeoutClose(addr)
	go u.ForwardStreamData(addr, stream)
}

func (u *UDPSession) DeleteStream(addr net.Addr) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if stream, ok := u.session[addr.String()]; ok {
		stream.Close()
	}
	delete(u.session, addr.String())
	delete(u.ping, addr.String())
}

func (u *UDPSession) Close() {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, stream := range u.session {
		stream.Close()
	}
	u.session = nil
	u.ping = nil
}

func (u *UDPSession) ForwardStreamData(addr net.Addr, stream *quic.Stream) {
	for {
		// Read data from QUIC stream with length prefix
		data, err := StreamReadWithLength(stream, 0)
		if err != nil {
			return
		}
		// Write data back to UDP addr
		_, err = u.ln.WriteTo(data, addr)
		if err != nil {
			return
		}
		select {
		case u.ping[addr.String()] <- struct{}{}:
		default:
		}

		log.Debugf("UDP data forwarded to %s, %d bytes", addr.String(), len(data))
	}
}

func (u *UDPSession) TimeoutClose(addr net.Addr) {
	timer := time.NewTimer(1 * time.Minute)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			u.DeleteStream(addr)
			log.Infof("UDP stream to %s timed out and closed", addr.String())
			return
		case <-u.ping[addr.String()]:
			timer.Reset(1 * time.Minute)
		}
	}
}
