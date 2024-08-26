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
	"enr:-JS4QHQ9Aq02CgtUe2bjoup1YWn6QB0Db8OVXvCeTijDRPKsSqibt5OfJpz3Veg0-9S6eJZmm883gpztfslUErat_M2GAZGN3iCVgmlkgnY0gmlwhI_GbfmEb3ZlcoQAAAAAiXNlY3AyNTZrMaEDri_DUGOyWhykON3vR5XhyTV9HwYhp1_NG-ctM9X5fNqDdWRwgsc4",
	"enr:-JS4QCMC2ZdcJJHIeErB0nsKoMQpBglHOEYhoGlogZpjNo7QeRj0VK14R1Qaovq7QUJKcFqa7shYtnhWokuXsALuUUSGAZGN3iBdgmlkgnY0gmlwhJgq4mWEb3ZlcoQAAAAAiXNlY3AyNTZrMaECVAeRN5aXm2G-E4EWrZTa7zsaoUpnl_WcFjghDQ-XJZSDdWRwgsc4",
}

var DolphinV5Bootnodes = []string{
	"enr:-JS4QFSQ8R7E4UaeiwMGfp4PNh5L-rSoVJG2BI-b60rqPl1EVg9RxW23NDqZ6dHkFvNulG5ifyH9dAydB1EI4eEEFVSGAZFLTQ7EgmlkgnY0gmlwhIDHSxeEb3ZlcoQAAAAAiXNlY3AyNTZrMaEDq9XrhVPCGXchqPI2yMyQ9GfFXEZ7fcayBfmjq0b0Iz2DdWRwgsc4",
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
