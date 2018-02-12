package main

import (
	"bytes"
	"fmt"

	"github.com/golang/glog"
	"github.com/taktv6/tbgp/packet"
)

func main() {
	buf := bytes.NewBuffer([]byte{1, 2, 3})
	pkt, err := packet.Decode(buf)
	if err != nil {
		glog.Exitf("Unable to decode BGP packet: %v", err)
	}

	fmt.Printf("BGP Packet: %v\n", pkt)
}
