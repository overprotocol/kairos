// Copyright 2015 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

// bootnode runs a bootstrap node for the Ethereum Discovery Protocol.
package main

import (
	"crypto/ecdsa"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/p2p/nat"
	"github.com/ethereum/go-ethereum/p2p/netutil"
)

func main() {
	var (
		listenAddr  = flag.String("addr", ":30301", "listen address")
		genKey      = flag.String("genkey", "", "generate a node key")
		writeAddr   = flag.Bool("writeaddress", false, "write out the node's public key and quit")
		nodeKeyFile = flag.String("nodekey", "", "private key filename")
		nodeKeyHex  = flag.String("nodekeyhex", "", "private key as hex (for testing)")
		natdesc     = flag.String("nat", "none", "port mapping mechanism (any|none|upnp|pmp|pmp:<IP>|extip:<IP>)")
		netrestrict = flag.String("netrestrict", "", "restrict network communication to the given IP networks (CIDR masks)")
		runv5       = flag.Bool("v5", false, "run a v5 topic discovery bootnode")
		verbosity   = flag.Int("verbosity", 3, "log verbosity (0-5)")
		vmodule     = flag.String("vmodule", "", "log verbosity pattern")
		extIP       = flag.String("external-ip", "", "external ip of bootnode")

		nodeKey *ecdsa.PrivateKey
		err     error
	)
	flag.Parse()

	glogger := log.NewGlogHandler(log.NewTerminalHandler(os.Stderr, false))
	slogVerbosity := log.FromLegacyLevel(*verbosity)
	glogger.Verbosity(slogVerbosity)
	glogger.Vmodule(*vmodule)
	log.SetDefault(log.NewLogger(glogger))

	natm, err := nat.Parse(*natdesc)
	if err != nil {
		utils.Fatalf("-nat: %v", err)
	}
	switch {
	case *genKey != "":
		nodeKey, err = crypto.GenerateKey()
		if err != nil {
			utils.Fatalf("could not generate key: %v", err)
		}
		if err = crypto.SaveECDSA(*genKey, nodeKey); err != nil {
			utils.Fatalf("%v", err)
		}
		if !*writeAddr {
			return
		}
	case *nodeKeyFile == "" && *nodeKeyHex == "":
		utils.Fatalf("Use -nodekey or -nodekeyhex to specify a private key")
	case *nodeKeyFile != "" && *nodeKeyHex != "":
		utils.Fatalf("Options -nodekey and -nodekeyhex are mutually exclusive")
	case *nodeKeyFile != "":
		if nodeKey, err = crypto.LoadECDSA(*nodeKeyFile); err != nil {
			utils.Fatalf("-nodekey: %v", err)
		}
	case *nodeKeyHex != "":
		if nodeKey, err = crypto.HexToECDSA(*nodeKeyHex); err != nil {
			utils.Fatalf("-nodekeyhex: %v", err)
		}
	}

	if *writeAddr {
		fmt.Printf("%x\n", crypto.FromECDSAPub(&nodeKey.PublicKey)[1:])
		os.Exit(0)
	}

	var paddr *net.UDPAddr
	if *extIP != "" {
		ipForENR := fmt.Sprintf("%s%s", *extIP, *listenAddr)
		fmt.Println("address for enr : ", ipForENR)

		paddr, err = net.ResolveUDPAddr("udp", ipForENR)
		if err != nil {
			utils.Fatalf("-ResolveUDPAddr: %v", err)
		}
	} else {
		fmt.Println("External IP for bootnode is needed")
		os.Exit(0)
	}

	var restrictList *netutil.Netlist
	if *netrestrict != "" {
		restrictList, err = netutil.ParseNetlist(*netrestrict)
		if err != nil {
			utils.Fatalf("-netrestrict: %v", err)
		}
	}

	cfg := discover.Config{
		PrivateKey:  nodeKey,
		NetRestrict: restrictList,
	}

	if *runv5 {
		ipAddr, err := ExternalIP()
		if err != nil {
			utils.Fatalf("%v", err)
		}
		listener := createListener(ipAddr, paddr, cfg)

		// Write the enr to a file.
		err = os.WriteFile("./kairos_enr.txt", []byte(listener.Self().String()), 0600)
		if err != nil {
			utils.Fatalf("Failed to write to file: %v", err)
		}
		fmt.Println("kairos_enr.txt file written successfully!")
	} else {
		addr, err := net.ResolveUDPAddr("udp", *listenAddr)
		if err != nil {
			utils.Fatalf("-ResolveUDPAddr: %v", err)
		}
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			utils.Fatalf("-ListenUDP: %v", err)
		}

		realaddr := conn.LocalAddr().(*net.UDPAddr)
		if natm != nil {
			if !realaddr.IP.IsLoopback() {
				go nat.Map(natm, nil, "udp", realaddr.Port, realaddr.Port, "ethereum discovery")
			}
			if ext, err := natm.ExternalIP(); err == nil {
				realaddr = &net.UDPAddr{IP: ext, Port: realaddr.Port}
			}
		}

		printNotice(&nodeKey.PublicKey, *realaddr)

		db, _ := enode.OpenDB("")
		ln := enode.NewLocalNode(db, nodeKey)
		if _, err := discover.ListenUDP(conn, ln, cfg); err != nil {
			utils.Fatalf("%v", err)
		}
	}
	fmt.Println("Bootnode started")

	select {}
}

func createListener(ipAddr string, addr *net.UDPAddr, cfg discover.Config) *discover.UDPv5 {
	ip := net.ParseIP(ipAddr)
	if ip.To4() == nil {
		utils.Fatalf("IPV4 address not provided instead %s was provided", ipAddr)
	}
	var bindIP net.IP
	var networkVersion string
	switch {
	case ip.To16() != nil && ip.To4() == nil:
		bindIP = net.IPv6zero
		networkVersion = "udp6"
	case ip.To4() != nil:
		bindIP = net.IPv4zero
		networkVersion = "udp4"
	default:
		utils.Fatalf("Valid ip address not provided instead %s was provided", ipAddr)
	}
	udpAddr := &net.UDPAddr{
		IP:   bindIP,
		Port: addr.Port,
	}
	conn, err := net.ListenUDP(networkVersion, udpAddr)
	if err != nil {
		utils.Fatalf("%v", err)
	}
	localNode, err := createLocalNode(cfg.PrivateKey, addr)
	if err != nil {
		utils.Fatalf("%v", err)
	}

	listener, err := discover.ListenV5(conn, localNode, cfg)
	if err != nil {
		utils.Fatalf("%v", err)
	}
	return listener
}

func createLocalNode(privKey *ecdsa.PrivateKey, addr *net.UDPAddr) (*enode.LocalNode, error) {
	db, err := enode.OpenDB("")
	if err != nil {
		return nil, fmt.Errorf("Could not open node's peer database %v", err)
	}
	external := net.ParseIP(addr.IP.String())

	localNode := enode.NewLocalNode(db, privKey)
	localNode.Set(enr.WithEntry("over", [4]byte{0}))
	localNode.SetFallbackIP(external)
	localNode.SetFallbackUDP(addr.Port)

	return localNode, nil
}

func printNotice(nodeKey *ecdsa.PublicKey, addr net.UDPAddr) {
	if addr.IP.IsUnspecified() {
		addr.IP = net.IP{127, 0, 0, 1}
	}
	n := enode.NewV4(nodeKey, addr.IP, 0, addr.Port)
	enodeVal := n.URLv4()
	fmt.Println(enodeVal)
	// Write the enr to a file.
	err := os.WriteFile("./enode.txt", []byte(enodeVal), 0600)
	if err != nil {
		utils.Fatalf("Failed to write to file: %v", err)
	}
	fmt.Println("enode.txt file written successfully!")
	fmt.Println("Note: you're using cmd/bootnode, a developer tool.")
	fmt.Println("We recommend using a regular node as bootstrap node for production deployments.")
}

// ExternalIP returns the first IPv4/IPv6 available.
func ExternalIP() (string, error) {
	ips, err := ipAddrs()
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "127.0.0.1", nil
	}
	return ips[0].String(), nil
}

// ipAddrs returns all the valid IPs available.
func ipAddrs() ([]net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var ipAddrs []net.IP
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			ipAddrs = append(ipAddrs, ip)
		}
	}
	return SortAddresses(ipAddrs), nil
}

// SortAddresses sorts a set of addresses in the order of
// ipv4 -> ipv6.
func SortAddresses(ipAddrs []net.IP) []net.IP {
	sort.Slice(ipAddrs, func(i, j int) bool {
		return ipAddrs[i].To4() != nil && ipAddrs[j].To4() == nil
	})
	return ipAddrs
}
