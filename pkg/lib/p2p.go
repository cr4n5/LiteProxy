package lib

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/cr4n5/liteproxy/common"
	"github.com/cr4n5/liteproxy/config"
	"github.com/pion/stun/v2"
	"github.com/quic-go/quic-go"
	log "github.com/sirupsen/logrus"
)

// util
type ChangedAddress struct {
	IP   net.IP
	Port int
}

func (s *ChangedAddress) GetFrom(m *stun.Message) error {
	a := (*stun.MappedAddress)(s)
	return a.GetFromAs(m, stun.AttrChangedAddress)
}

func (s *ChangedAddress) String() string {
	return net.JoinHostPort(s.IP.String(), strconv.Itoa(s.Port))
}

// -----------------------------
// ------------STUN-------------
var responseTimeout = 3 * time.Second

type Message struct {
	Body []byte
	Addr string
}

type stunResponse struct {
	externalAddr string
	otherAddr    string
}

type discoverConn struct {
	conn *net.UDPConn

	localAddr   net.Addr
	messageChan chan *Message
}

// If the localAddr is empty, it will listen on a random port.
func Discover(stunServers []string, localAddr string) ([]string, net.Addr, error) {
	// create a discoverConn and get response from messageChan
	discoverConn, err := listen(localAddr)
	if err != nil {
		return nil, nil, err
	}
	defer discoverConn.Close()

	go discoverConn.readLoop()

	addresses := make([]string, 0, len(stunServers))
	for _, addr := range stunServers {
		// get external address from stun server
		externalAddrs, err := discoverConn.discoverFromStunServer(addr)
		if err != nil {
			return nil, nil, err
		}
		addresses = append(addresses, externalAddrs...)
	}
	return addresses, discoverConn.localAddr, nil
}

func listen(localAddr string) (*discoverConn, error) {
	var local *net.UDPAddr
	if localAddr != "" {
		addr, err := net.ResolveUDPAddr("udp4", localAddr)
		if err != nil {
			return nil, err
		}
		local = addr
	}
	conn, err := net.ListenUDP("udp4", local)
	if err != nil {
		return nil, err
	}

	return &discoverConn{
		conn:        conn,
		localAddr:   conn.LocalAddr(),
		messageChan: make(chan *Message, 10),
	}, nil
}

func (c *discoverConn) Close() error {
	if c.messageChan != nil {
		close(c.messageChan)
		c.messageChan = nil
	}
	return c.conn.Close()
}

func (c *discoverConn) readLoop() {
	for {
		buf := make([]byte, 1024)
		n, addr, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		buf = buf[:n]

		c.messageChan <- &Message{
			Body: buf,
			Addr: addr.String(),
		}
	}
}

func (c *discoverConn) doSTUNRequest(addr string) (*stunResponse, error) {
	serverAddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, err
	}
	request, err := stun.Build(stun.TransactionID, stun.BindingRequest)
	if err != nil {
		return nil, err
	}

	if err = request.NewTransactionID(); err != nil {
		return nil, err
	}
	if _, err := c.conn.WriteTo(request.Raw, serverAddr); err != nil {
		return nil, err
	}

	var m stun.Message
	select {
	case msg := <-c.messageChan:
		m.Raw = msg.Body
		if err := m.Decode(); err != nil {
			return nil, err
		}
	case <-time.After(responseTimeout):
		return nil, fmt.Errorf("wait response from stun server timeout")
	}
	xorAddrGetter := &stun.XORMappedAddress{}
	mappedAddrGetter := &stun.MappedAddress{}
	changedAddrGetter := ChangedAddress{}
	otherAddrGetter := &stun.OtherAddress{}

	resp := &stunResponse{}
	if err := mappedAddrGetter.GetFrom(&m); err == nil {
		resp.externalAddr = mappedAddrGetter.String()
	}
	if err := xorAddrGetter.GetFrom(&m); err == nil {
		resp.externalAddr = xorAddrGetter.String()
	}
	if err := changedAddrGetter.GetFrom(&m); err == nil {
		resp.otherAddr = changedAddrGetter.String()
	}
	if err := otherAddrGetter.GetFrom(&m); err == nil {
		resp.otherAddr = otherAddrGetter.String()
	}
	return resp, nil
}

func (c *discoverConn) discoverFromStunServer(addr string) ([]string, error) {
	resp, err := c.doSTUNRequest(addr)
	if err != nil {
		return nil, err
	}
	if resp.externalAddr == "" {
		return nil, fmt.Errorf("no external address found")
	}

	externalAddrs := make([]string, 0, 2)
	externalAddrs = append(externalAddrs, resp.externalAddr)

	if resp.otherAddr == "" {
		return externalAddrs, nil
	}

	// find external address from changed address
	resp, err = c.doSTUNRequest(resp.otherAddr)
	if err != nil {
		return nil, err
	}
	if resp.externalAddr == "" {
		return nil, fmt.Errorf("no external address found from changed address")
	}
	externalAddrs = append(externalAddrs, resp.externalAddr)
	return externalAddrs, nil
}

// ------------------------------------
// --- P2P connection establishment ---
const (
	Mode0 = 0
	Mode1 = 1
	Mode2 = 2

	EasyNat = 3
	HardNat = 4

	Sender   = 5
	Receiver = 6
)

type NatRule struct {
	Mode          int
	ExternalAddr  string
	PeerAddr      string
	PeerIP        net.IP
	PeerPort      int
	Role          int
	RangePeerPort []int
}

func EstablishP2PConnection(ctx context.Context, cfg config.Config, stream *quic.Stream) (*quic.Conn, error) {
	defer stream.Close()
	// Discover external addresses
	externalAddrs, localAddr, err := Discover([]string{cfg.StunServer}, "")
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(externalAddrs)
	if err != nil {
		return nil, err
	}
	var natRule NatRule
	if cfg.Mode == "server" {
		// Read peer external addresses
		peerData, err := StreamReadWithLength(stream, 0)
		if err != nil {
			return nil, common.TranslateStreamError(err)
		}
		var peerExternalAddrs []string
		err = json.Unmarshal(peerData, &peerExternalAddrs)
		if err != nil {
			return nil, err
		}
		log.Infof("(P2P) External Addrs %v, Peer External Addrs %v", externalAddrs, peerExternalAddrs)
		// analyze addresses
		var peerNatRule NatRule
		natRule, peerNatRule, err = AnalyzeNatRule(externalAddrs, peerExternalAddrs)
		if err != nil {
			return nil, err
		}
		// send nat rule to client
		natRuleData, err := json.Marshal(peerNatRule)
		if err != nil {
			return nil, err
		}
		_, err = StreamWriteWithLength(stream, natRuleData, 0)
		if err != nil {
			return nil, err
		}
	} else {
		// send external addresses to server
		_, err = StreamWriteWithLength(stream, data, 0)
		if err != nil {
			return nil, err
		}
		// read nat rule from server
		natRuleData, err := StreamReadWithLength(stream, 0)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(natRuleData, &natRule)
		if err != nil {
			return nil, err
		}
	}

	// make nat hole
	log.Infof("(P2P) Starting NAT traversal with role: %s, mode: %s", map[int]string{Sender: "Sender", Receiver: "Receiver"}[natRule.Role], map[int]string{Mode0: "Mode0", Mode1: "Mode1", Mode2: "Mode2"}[natRule.Mode])
	p2pcontext, cancel := context.WithCancel(ctx)
	defer cancel()
	natHole, err := NewNatHole(p2pcontext, &cfg, natRule, localAddr)
	if err != nil {
		return nil, err
	}
	rContext, rCancel := context.WithCancel(p2pcontext)
	defer rCancel()
	go natHole.MakeNatHole(p2pcontext, rContext)

	// wait for result
	select {
	case err := <-natHole.resultChan:
		if err != nil {
			return nil, err
		}
		rCancel()
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
			return nil, fmt.Errorf("failed to dial P2P connection")
		}
	case <-time.After(60 * time.Second):
		return nil, fmt.Errorf("establish P2P connection timeout")
	}
	return nil, fmt.Errorf("failed to establish P2P connection")
}

func AnalyzeNatRule(externalAddrs, peerExternalAddrs []string) (natRule, peerNatRule NatRule, err error) {
	// analyze nat type
	natType, peerNatRule, err := AnalyzeNatType(externalAddrs)
	if err != nil {
		return natRule, peerNatRule, err
	}
	peerNatType, natRule, err := AnalyzeNatType(peerExternalAddrs)
	if err != nil {
		return natRule, peerNatRule, err
	}
	natRule.ExternalAddr = externalAddrs[0]
	peerNatRule.ExternalAddr = peerExternalAddrs[0]
	// determine nat traversal mode
	if natType == EasyNat && peerNatType == EasyNat { // both easy
		natRule.Mode = Mode0
		peerNatRule.Mode = Mode0
		natRule.Role = Receiver // default (SERVER) as receiver
		peerNatRule.Role = Sender
	} else if natType+peerNatType == EasyNat+HardNat { // one easy, one hard
		if natRule.RangePeerPort == nil || peerNatRule.RangePeerPort == nil { // can not predict port
			natRule.Mode = Mode2
			peerNatRule.Mode = Mode2
		} else { // can predict port
			natRule.Mode = Mode1
			peerNatRule.Mode = Mode1
		}

		if natType == EasyNat { // easy nat as sender
			natRule.Role = Sender
			peerNatRule.Role = Receiver
		} else {
			natRule.Role = Receiver
			peerNatRule.Role = Sender
		}
	}
	return natRule, peerNatRule, nil
}

// From: max(port-difference-5, port-10, 1),
// To:   min(port+difference+5, port+10, 65535),
func AnalyzeNatType(addrs []string) (natType int, natRule NatRule, err error) {
	ip0, port0Str, err := net.SplitHostPort(addrs[0])
	if err != nil {
		return 0, NatRule{}, err
	}
	port0, err := strconv.Atoi(port0Str)
	if err != nil {
		return 0, NatRule{}, err
	}
	ip1, port1Str, err := net.SplitHostPort(addrs[1])
	if err != nil {
		return 0, NatRule{}, err
	}
	port1, err := strconv.Atoi(port1Str)
	if err != nil {
		return 0, NatRule{}, err
	}
	natRule = NatRule{
		PeerAddr: addrs[0],
		PeerIP:   net.ParseIP(ip0),
		PeerPort: port0,
	}
	if ip0 == ip1 {
		if port0 == port1 {
			natType = EasyNat
			natRule.RangePeerPort = []int{port0}
		} else {
			natType = HardNat
			difference := max(port0-port1, port1-port0)
			if difference >= 1 && difference <= 5 {
				From := max(port0-difference-5, port0-10, 1)
				To := min(port0+difference+5, port0+10, 65535)
				for p := From; p <= To; p++ {
					natRule.RangePeerPort = append(natRule.RangePeerPort, p)
				}
			}
		}
	} else {
		return 0, NatRule{}, fmt.Errorf("different IPs detected: %s vs %s", ip0, ip1)
	}
	return natType, natRule, nil
}

// -----------------------------
// ----------NatHole------------
type NatHole struct {
	natRule    NatRule
	udpConn    []*net.UDPConn
	peerPort   []int
	accessKey  string
	resultChan chan error
	resultConn *net.UDPConn
	mu         sync.Mutex
}

func NewNatHole(ctx context.Context, cfg *config.Config, natRule NatRule, localAddr net.Addr) (*NatHole, error) {
	natHole := &NatHole{
		natRule:    natRule,
		udpConn:    make([]*net.UDPConn, 0),
		accessKey:  cfg.AccessKey,
		resultChan: make(chan error, 1),
	}

	tmpConn, err := net.ListenUDP("udp4", localAddr.(*net.UDPAddr))
	if err != nil {
		return nil, err
	}
	natHole.udpConn = append(natHole.udpConn, tmpConn)
	natHole.peerPort = append(natHole.peerPort, natRule.PeerPort)
	go natHole.Listen(ctx, tmpConn)
	go natHole.Send(ctx, tmpConn, net.JoinHostPort(natRule.PeerIP.String(), strconv.Itoa(natRule.PeerPort)))
	return natHole, nil
}

func (nh *NatHole) MakeNatHole(p2pctx, rctx context.Context) {
	switch nh.natRule.Mode {
	case Mode0:
		select {
		case <-p2pctx.Done():
			return
		case <-rctx.Done():
			return
		case <-time.After(10 * time.Second):
			// timeout
			log.Infof("(P2P) Mode0 timeout, proceeding to Mode1")
		}
		go nh.MakeMode1Hole(p2pctx)
		select {
		case <-p2pctx.Done():
			return
		case <-rctx.Done():
			return
		case <-time.After(10 * time.Second):
			// timeout
			log.Infof("(P2P) Mode1 timeout, proceeding to Mode2")
		}
		go nh.MakeMode2Hole(p2pctx)
	case Mode1:
		go nh.MakeMode1Hole(p2pctx)
		select {
		case <-p2pctx.Done():
			return
		case <-rctx.Done():
			return
		case <-time.After(10 * time.Second):
			// timeout
			log.Infof("(P2P) Mode1 timeout, proceeding to Mode2")
		}
		go nh.MakeMode2Hole(p2pctx)
	case Mode2:
		go nh.MakeMode2Hole(p2pctx)
	default:
		nh.SendChannel(fmt.Errorf("unknown NAT traversal mode: %d", nh.natRule.Mode))
	}
}

func (nh *NatHole) SendChannel(err error) {
	select {
	case nh.resultChan <- err:
	default:
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
			_, err = conn.WriteToUDP([]byte(nh.accessKey), peerAddr)
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
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
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
			_, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok {
					if netErr.Timeout() {
						log.Debugf("(P2P) Listen timeout on local addr %s, continue...", conn.LocalAddr().String())
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
				log.Infof("(P2P) Successfully received msg with peer %s via local addr %s", addr.String(), conn.LocalAddr().String())
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
			if port != nh.natRule.PeerPort {
				go nh.Send(ctx, conn, net.JoinHostPort(nh.natRule.PeerIP.String(), strconv.Itoa(port)))
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
			tmpConn, err := net.ListenUDP("udp4", nil)
			if err != nil {
				nh.SendChannel(err)
				return
			}
			nh.udpConn = append(nh.udpConn, tmpConn)
			go nh.Listen(ctx, tmpConn)
			go nh.Send(ctx, tmpConn, net.JoinHostPort(nh.natRule.PeerIP.String(), strconv.Itoa(nh.natRule.PeerPort)))
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
			for {
				port := rand.IntN(65535-1024) + 1024
				if !slices.Contains(nh.peerPort, port) {
					go nh.Send(ctx, conn, net.JoinHostPort(nh.natRule.PeerIP.String(), strconv.Itoa(port)))
					nh.peerPort = append(nh.peerPort, port)
					break
				}
			}
			time.Sleep(10 * time.Millisecond)
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
			tmpConn, err := net.ListenUDP("udp4", nil)
			if err != nil {
				nh.SendChannel(err)
				return
			}
			nh.udpConn = append(nh.udpConn, tmpConn)
			go nh.Listen(ctx, tmpConn)
			go nh.Send(ctx, tmpConn, net.JoinHostPort(nh.natRule.PeerIP.String(), strconv.Itoa(nh.natRule.PeerPort)))
			time.Sleep(10 * time.Millisecond)
			i++
		}
	}
}
