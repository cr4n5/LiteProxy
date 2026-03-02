package p2p

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// -----------------------------
// ----------NatHole------------
type NatHole struct {
	natRule    NatRule
	udpConn    []*net.UDPConn
	peerPort   []int
	resultChan chan error
	resultConn *net.UDPConn
	mu         sync.RWMutex
}

func (nh *NatHole) IsResultReady() bool {
	nh.mu.RLock()
	defer nh.mu.RUnlock()
	return nh.resultConn != nil
}

func (nh *NatHole) SendChannel(err error) {
	select {
	case nh.resultChan <- err:
	default:
	}
}

func NewNatHole(ctx context.Context, natRule NatRule, localAddr net.Addr) (*NatHole, error) {
	natHole := &NatHole{
		natRule:    natRule,
		udpConn:    make([]*net.UDPConn, 0),
		resultChan: make(chan error, 1),
	}

	tmpConn, err := net.ListenUDP("udp4", localAddr.(*net.UDPAddr))
	if err != nil {
		return nil, err
	}

	natHole.udpConn = append(natHole.udpConn, tmpConn)
	natHole.peerPort = append(natHole.peerPort, natRule.PeerPort)

	go natHole.Listen(ctx, tmpConn)
	go natHole.Send(ctx, tmpConn, net.JoinHostPort(natRule.PeerIP, strconv.Itoa(natRule.PeerPort)))
	if natRule.OtherPeerIP != "" {
		go natHole.Send(ctx, tmpConn, net.JoinHostPort(natRule.OtherPeerIP, strconv.Itoa(natRule.PeerPort)))
	}

	return natHole, nil
}

func (nh *NatHole) MakeNatHole(p2pctx context.Context) {
	switch nh.natRule.Mode {
	case Mode0:
		select {
		case <-p2pctx.Done():
			return
		case <-time.After(5 * time.Second):
			// timeout
			if nh.IsResultReady() {
				return
			}
			log.Infof("(P2P) Mode0 timeout, proceeding to Mode1")
		}
		go nh.MakeMode1Hole(p2pctx)

		select {
		case <-p2pctx.Done():
			return
		case <-time.After(5 * time.Second):
			// timeout
			if nh.IsResultReady() {
				return
			}
			log.Infof("(P2P) Mode1 timeout, proceeding to Mode2")
		}
		go nh.MakeMode2Hole(p2pctx)

	case Mode1:
		go nh.MakeMode1Hole(p2pctx)

		select {
		case <-p2pctx.Done():
			return
		case <-time.After(5 * time.Second):
			// timeout
			if nh.IsResultReady() {
				return
			}
			log.Infof("(P2P) Mode1 timeout, proceeding to Mode2")
		}
		go nh.MakeMode2Hole(p2pctx)

	case Mode2:
		go nh.MakeMode2Hole(p2pctx)

	default:
		nh.SendChannel(fmt.Errorf("unknown NAT traversal mode: %d", nh.natRule.Mode))
	}
}

func (nh *NatHole) Send(ctx context.Context, conn *net.UDPConn, peerAddr string) {
	log.Debugf("(P2P) Send started on local addr %s to peer addr %s", conn.LocalAddr().String(), peerAddr)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			// send packet to peer
			peerAddr, err := net.ResolveUDPAddr("udp4", peerAddr)
			if err != nil {
				nh.SendChannel(err)
				return
			}

			_, err = conn.WriteToUDP([]byte{0x00}, peerAddr)
			if err != nil {
				nh.SendChannel(err)
				return
			}
			time.Sleep(2 * time.Second)
		}
	}
}

func (nh *NatHole) Listen(ctx context.Context, conn *net.UDPConn) {
	log.Debugf("(P2P) Listen started on local addr %s", conn.LocalAddr().String())
	buf := make([]byte, 65535)
	defer func() {
		if conn != nh.resultConn {
			conn.Close()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			if nh.IsResultReady() {
				return
			}

			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok {
					if netErr.Timeout() {
						// log.Debugf("(P2P) Listen timeout on local addr %s, continue...", conn.LocalAddr().String())
						continue
					}
				}
				nh.SendChannel(err)
				return
			}

			nh.mu.Lock()
			if nh.resultConn == nil {
				nh.resultConn = conn
				// set no deadline
				conn.SetReadDeadline(time.Time{})
				log.Infof("(P2P) Received msg with peer %s via local addr %s", addr.String(), conn.LocalAddr().String())
				go nh.Send(ctx, conn, addr.String())
				nh.SendChannel(nil)
			}
			nh.mu.Unlock()

			return
		}
	}
}

func (nh *NatHole) MakeMode1Hole(ctx context.Context) {
	switch nh.natRule.Role {
	case Sender:
		conn := nh.udpConn[0]
		for _, port := range nh.natRule.RangePeerPort {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if nh.IsResultReady() {
				return
			}

			if port != nh.natRule.PeerPort {
				go nh.Send(ctx, conn, net.JoinHostPort(nh.natRule.PeerIP, strconv.Itoa(port)))
				nh.peerPort = append(nh.peerPort, port)
			}
		}

	case Receiver:
		for i := 1; i < 10; i++ {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if nh.IsResultReady() {
				return
			}

			tmpConn, err := net.ListenUDP("udp4", nil)
			if err != nil {
				nh.SendChannel(err)
				return
			}
			nh.udpConn = append(nh.udpConn, tmpConn)

			go nh.Listen(ctx, tmpConn)
			go nh.Send(ctx, tmpConn, net.JoinHostPort(nh.natRule.PeerIP, strconv.Itoa(nh.natRule.PeerPort)))
		}
	}
}

func (nh *NatHole) MakeMode2Hole(ctx context.Context) {
	switch nh.natRule.Role {
	case Sender:
		conn := nh.udpConn[0]
		i := len(nh.peerPort)
		for i <= 1000 {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if nh.IsResultReady() {
				return
			}

			for {
				port := rand.IntN(65535-1024) + 1024
				if !slices.Contains(nh.peerPort, port) {
					if nh.natRule.OtherPeerIP != "" {
						go nh.Send(ctx, conn, net.JoinHostPort(nh.natRule.OtherPeerIP, strconv.Itoa(port)))
						i++
					}
					go nh.Send(ctx, conn, net.JoinHostPort(nh.natRule.PeerIP, strconv.Itoa(port)))
					nh.peerPort = append(nh.peerPort, port)

					break
				}
			}
			time.Sleep(15 * time.Millisecond)
			i++
		}

	case Receiver:
		i := len(nh.udpConn)
		for i <= 256 {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if nh.IsResultReady() {
				return
			}

			tmpConn, err := net.ListenUDP("udp4", nil)
			if err != nil {
				nh.SendChannel(err)
				return
			}
			nh.udpConn = append(nh.udpConn, tmpConn)
			go nh.Listen(ctx, tmpConn)
			go nh.Send(ctx, tmpConn, net.JoinHostPort(nh.natRule.PeerIP, strconv.Itoa(nh.natRule.PeerPort)))

			time.Sleep(15 * time.Millisecond)
			i++
		}
	}
}
