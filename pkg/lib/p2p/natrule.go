package p2p

import (
	"errors"
	"fmt"
	"net"
	"strconv"
)

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
	Mode int
	// ExternalAddr  string
	PeerAddr      string
	PeerIP        string
	PeerPort      int
	Role          int
	RangePeerPort []int
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
	// natRule.ExternalAddr = externalAddrs[0]
	// peerNatRule.ExternalAddr = peerExternalAddrs[0]

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
	} else {
		return natRule, peerNatRule, errors.New("both hard nat is not supported")
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
		PeerIP:   ip0,
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
