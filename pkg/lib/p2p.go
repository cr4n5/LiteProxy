package lib

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/cr4n5/liteproxy/config"
	"github.com/pion/stun/v2"
	"github.com/quic-go/quic-go"
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
	// Discover external addresses
	externalAddrs, localAddr, err := Discover([]string{cfg.StunServer}, "")
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(externalAddrs)
	if err != nil {
		return nil, err
	}
	if cfg.Mode == "server" {
		// Read peer external addresses
		peerData, err := StreamReadWithLength(stream, 0)
		if err != nil {
			return nil, err
		}
		var peerExternalAddrs []string
		err = json.Unmarshal(peerData, &peerExternalAddrs)
		if err != nil {
			return nil, err
		}
		// analyze peer addresses
	} else {
		_, err = StreamWriteWithLength(stream, data, 0)
		if err != nil {
			return nil, err
		}
	}

	return nil, nil
}

func AnalyzeNatRule(externalAddrs, peerExternalAddrs []string) (natRule, peerNatRule NatRule, err error) {
	// analyze nat type
	natType, difference, err := AnalyzeNatType(externalAddrs)
	if err != nil {
		return natRule, peerNatRule, err
	}
	peerNatType, peerDifference, err := AnalyzeNatType(peerExternalAddrs)
	if err != nil {
		return natRule, peerNatRule, err
	}
	if natType == EasyNat && peerNatType == EasyNat {
		natRule = NatRule{
			Mode:         Mode0,
			ExternalAddr: externalAddrs[0],
			Role:         Receiver,
		}
		peerNatRule = NatRule{
			Mode:         Mode0,
			ExternalAddr: peerExternalAddrs[0],
			Role:         Sender,
		}
	}
	return natRule, peerNatRule, nil
}

func AnalyzeNatType(addrs []string) (natType int, difference int, err error) {
	ip0, port0Str, err := net.SplitHostPort(addrs[0])
	if err != nil {
		return 0, 0, err
	}
	port0, err := strconv.Atoi(port0Str)
	if err != nil {
		return 0, 0, err
	}
	ip1, port1Str, err := net.SplitHostPort(addrs[1])
	if err != nil {
		return 0, 0, err
	}
	port1, err := strconv.Atoi(port1Str)
	if err != nil {
		return 0, 0, err
	}
	if ip0 == ip1 {
		if port0 == port1 {
			natType = EasyNat
			difference = 0
		} else {
			natType = HardNat
			difference = max(port0-port1, port1-port0)
		}
	} else {
		return 0, 0, fmt.Errorf("different IPs detected: %s vs %s", ip0, ip1)
	}
	return natType, difference, nil
}
