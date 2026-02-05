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
	ln       net.PacketConn
	session  sync.Map
	ping     sync.Map
	creating sync.Map
}

func NewUDPSession(ln net.PacketConn) *UDPSession {
	return &UDPSession{
		ln: ln,
	}
}

func (u *UDPSession) GetOrCreateStream(ctx context.Context, route config.RouteConfig, bridgeConn *quic.Conn, addr net.Addr) (*quic.Stream, error) {
	stream, ok := u.GetStream(addr)
	if ok {
		return stream.(*quic.Stream), nil
	}

	// creating sync.Map to prevent duplicate creations
	actual, _ := u.creating.LoadOrStore(addr.String(), &sync.Mutex{})
	mu := actual.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()

	stream, ok = u.GetStream(addr)
	if ok {
		return stream.(*quic.Stream), nil
	}

	stream, err := HandConnToTarget(ctx, &route, bridgeConn)
	if err != nil {
		return nil, err
	}
	u.SetStream(addr, stream.(*quic.Stream), &route)

	return stream.(*quic.Stream), nil
}

func (u *UDPSession) GetStream(addr net.Addr) (any, bool) {
	stream, ok := u.session.Load(addr.String())
	if ok {
		pingCh, pingOk := u.ping.Load(addr.String())
		if pingOk {
			u.PingStream(pingCh)
		}
	}
	return stream, ok
}

func (u *UDPSession) SetStream(addr net.Addr, stream *quic.Stream, route *config.RouteConfig) {
	u.session.Store(addr.String(), stream)
	u.ping.Store(addr.String(), make(chan struct{}, 1))
	log.Infof("(UDP) UDP stream created for %s with target %s", addr.String(), route.ClientAddr)

	go u.TimeoutClose(addr, route)
	go u.ForwardStreamData(addr, stream, route)
}

func (u *UDPSession) DeleteStream(addr net.Addr) {
	if stream, ok := u.session.Load(addr.String()); ok {
		stream.(*quic.Stream).Close()
	}
	u.session.Delete(addr.String())
	u.ping.Delete(addr.String())
	u.creating.Delete(addr.String())
}

func (u *UDPSession) Close() {
	u.session.Range(func(key, value any) bool {
		value.(*quic.Stream).Close()
		return true
	})
	u.session = sync.Map{}
	u.ping = sync.Map{}
	u.creating = sync.Map{}
}

func (u *UDPSession) ForwardStreamData(addr net.Addr, stream *quic.Stream, route *config.RouteConfig) {
	pingCh, pingOk := u.ping.Load(addr.String())
	if !pingOk {
		log.Errorf("(UDP) ping channel for %s not found", addr.String())
		return
	}
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
		u.PingStream(pingCh)
		log.Debugf("(UDP) UDP data forwarded from target %s to %s, %d bytes", route.ClientAddr, addr.String(), len(data))
	}
}

func (u *UDPSession) TimeoutClose(addr net.Addr, route *config.RouteConfig) {
	timer := time.NewTimer(1 * time.Minute)
	defer timer.Stop()

	pingCh, pingOk := u.ping.Load(addr.String())
	if !pingOk {
		log.Errorf("(UDP) ping channel for %s not found", addr.String())
		return
	}
	for {
		select {
		case <-timer.C:
			u.DeleteStream(addr)
			log.Infof("(UDP) UDP stream for %s with target %s closed due to inactivity", addr.String(), route.ClientAddr)
			return
		case <-pingCh.(chan struct{}):
			timer.Reset(1 * time.Minute)
		}
	}
}

func (u *UDPSession) PingStream(pingCh any) {
	// Reset timeout timer
	select {
	case pingCh.(chan struct{}) <- struct{}{}:
	default:
	}
}
