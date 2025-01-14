package ethclient_test

import (
	"github.com/ethereum/go-ethereum/node"
)

var exampleNode *node.Node

// launch example server
func init() {
	config := &node.Config{
		HTTPHost: "127.0.0.1",
	}
	n, _, err := newTestBackend(config)
	if err != nil {
		panic("can't launch node: " + err.Error())
	}
	exampleNode = n
}
