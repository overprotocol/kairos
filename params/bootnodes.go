// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package params

// MainnetBootnodes are the enode URLs of the P2P bootstrap nodes running on
// the main Ethereum network.
var MainnetBootnodes = []string{}

var DolphinBootnodes = []string{}

var MainnetV5Bootnodes = []string{
	"enr:-JS4QD70J7PbKC-9XB5sYn-SWcoudeDYZeDqAE1efA6bX8FMdNSaJeYajFMiDcwWcloGrg0CyhU0Wy64LfI_TlDeVPCGAZOdApnxgmlkgnY0gmlwhJ31NHqEb3ZlcoQAAAAAiXNlY3AyNTZrMaEDL9b2ICPLhD22-nErr68hNE_Pgc7JTfQfKYqG9h6jXWWDdWRwgsc4",
	"enr:-JS4QHLj47rvFV0jnZH3KxJ3K__ZhsmcW1Ueg4dI50tzNtiEBRnk4UZ7u1r-OSlkS-yEgSGbsTmcZf-16_QlYwZ6ENGGAZOdApnxgmlkgnY0gmlwhJ31MLmEb3ZlcoQAAAAAiXNlY3AyNTZrMaEDzDrmOEX8MOD5AA_tJpVE7D1PpggFdhU_eiMEvTq949mDdWRwgsc4",
}

var DolphinV5Bootnodes = []string{
	"enr:-JS4QJtb_JQpP9_7nn1-GtgrkWlwC-uM3V645xD-IcRJ6uJ1czjx9j5nCqonynrk1bo8vMr2tje00RbUKhT0rQakNBqGAZOQdrE_gmlkgnY0gmlwhKesTPSEb3ZlcoQAAAAAiXNlY3AyNTZrMaED_VBfi1aLnR_5kufyq6U0vp7aYCWXWlABlSu0YeKRtQyDdWRwgsc4",
}

// No DNSNetwork for now
// const dnsPrefix = "enrtree://AKA3AM6LPBYEUDMVNU3BSVQJ5AD45Y7YPOHJLEF6W26QOE4VTUDPE@"

// // KnownDNSNetwork returns the address of a public DNS-based node list for the given
// // genesis hash and protocol. See https://github.com/ethereum/discv4-dns-lists for more
// // information.
// func KnownDNSNetwork(genesis common.Hash, protocol string) string {
// 	var net string
// 	switch genesis {
// 	case MainnetGenesisHash:
// 		net = "mainnet"
// 	case GoerliGenesisHash:
// 		net = "goerli"
// 	case SepoliaGenesisHash:
// 		net = "sepolia"
// 	case HoleskyGenesisHash:
// 		net = "holesky"
// 	default:
// 		return ""
// 	}
// 	return dnsPrefix + protocol + "." + net + ".ethdisco.net"
// }
