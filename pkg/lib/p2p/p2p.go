package p2p

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/cr4n5/liteproxy/common"
	"github.com/cr4n5/liteproxy/config"
	"github.com/cr4n5/liteproxy/pkg/lib"
	"github.com/quic-go/quic-go"
	log "github.com/sirupsen/logrus"
)

func EstablishP2PConnection(ctx context.Context, cfg config.Config, stream *quic.Stream) (*quic.Conn, error) {
	defer stream.Close()
	// get nat rule
	natRule, localAddr, err := GetNatRule(ctx, cfg, stream)
	if err != nil {
		return nil, err
	}

	// make nat hole
	log.Infof("(P2P) Starting NAT traversal with role: %s, mode: %s", map[int]string{Sender: "Sender", Receiver: "Receiver"}[natRule.Role], map[int]string{Mode0: "Mode0", Mode1: "Mode1", Mode2: "Mode2"}[natRule.Mode])
	p2pcontext, cancel := context.WithCancel(ctx)
	defer cancel()
	natHole, err := NewNatHole(p2pcontext, *natRule, localAddr)
	if err != nil {
		return nil, err
	}
	go natHole.MakeNatHole(p2pcontext)

	// wait for p2p connection
	return WaitP2PConnection(ctx, *natRule, natHole)
}

func GetNatRule(ctx context.Context, cfg config.Config, stream *quic.Stream) (*NatRule, net.Addr, error) {
	// Discover external addresses
	externalAddrs, localAddr, err := Discover([]string{cfg.StunServer}, "")
	if err != nil {
		stream.CancelWrite(common.ErrNatType)
		return nil, nil, err
	}
	log.Infof("(P2P) Discovered external addresses: %v", externalAddrs)
	data, err := json.Marshal(externalAddrs)
	if err != nil {
		return nil, nil, err
	}
	var natRule NatRule
	if cfg.Mode == "server" {
		// Read peer external addresses
		peerData, err := lib.StreamReadWithLength(stream, 10)
		if err != nil {
			return nil, nil, common.TranslateStreamError(err)
		}
		var peerExternalAddrs []string
		err = json.Unmarshal(peerData, &peerExternalAddrs)
		if err != nil {
			return nil, nil, err
		}
		log.Infof("(P2P) Peer External Addrs %v", peerExternalAddrs)
		// analyze addresses
		var peerNatRule NatRule
		natRule, peerNatRule, err = AnalyzeNatRule(externalAddrs, peerExternalAddrs)
		if err != nil {
			stream.CancelWrite(common.ErrNatType)
			return nil, nil, err
		}
		// send nat rule to client
		natRuleData, err := json.Marshal(peerNatRule)
		if err != nil {
			return nil, nil, err
		}
		_, err = lib.StreamWriteWithLength(stream, natRuleData, 0)
		if err != nil {
			return nil, nil, common.TranslateStreamError(err)
		}
	} else {
		// send external addresses to server
		_, err = lib.StreamWriteWithLength(stream, data, 0)
		if err != nil {
			return nil, nil, common.TranslateStreamError(err)
		}
		// read nat rule from server
		natRuleData, err := lib.StreamReadWithLength(stream, 10)
		if err != nil {
			return nil, nil, common.TranslateStreamError(err)
		}
		err = json.Unmarshal(natRuleData, &natRule)
		if err != nil {
			return nil, nil, err
		}
	}
	return &natRule, localAddr, nil
}

func WaitP2PConnection(ctx context.Context, natRule NatRule, natHole *NatHole) (*quic.Conn, error) {
	// wait for result
	select {
	case err := <-natHole.resultChan:
		if err != nil {
			return nil, err
		}
		// establish quic connection over nat hole
		switch natRule.Role {
		case Sender:
			ln, err := quic.Listen(natHole.resultConn, common.GenerateTLSConfig(), common.QuicConfig)
			defer ln.Close()
			if err != nil {
				return nil, err
			}
			ctxTimeout, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			return ln.Accept(ctxTimeout)
		case Receiver:
			peerAddr, err := net.ResolveUDPAddr("udp4", natRule.PeerAddr)
			if err != nil {
				return nil, err
			}
			for i := range 15 {
				ctxTimeout, cancel := context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
				conn, err := quic.Dial(ctxTimeout, natHole.resultConn, peerAddr, common.GenerateClientTLSConfig(), common.QuicConfig)
				if err != nil {
					log.Errorf("(P2P) failed to dial P2P connection, attempt %d: %v", i+1, err)
					continue
				}
				go func() {
					select {
					case <-conn.Context().Done():
					case <-ctx.Done():
					}
					natHole.resultConn.Close()
				}()
				return conn, nil
			}
			natHole.resultConn.Close()
		}
	case <-time.After(60 * time.Second):
		// timeout
	}
	return nil, fmt.Errorf("establish P2P connection timeout")
}
