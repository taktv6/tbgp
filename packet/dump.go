package packet

import (
	"fmt"
	"net"
)

func (b *BGPMessage) Dump() {
	fmt.Printf("Type: %d Length: %d\n", b.Header.Type, b.Header.Length)
	switch b.Header.Type {
	case OpenMsg:
		o := b.Body.(*BGPOpen)
		fmt.Printf("OPEN Message:\n")
		fmt.Printf("\tVersion: %d\n", o.Version)
		fmt.Printf("\tASN: %d\n", o.AS)
		fmt.Printf("\tHoldTime: %d\n", o.HoldTime)
		fmt.Printf("\tBGP Identifier: %d\n", o.BGPIdentifier)
	case UpdateMsg:
		u := b.Body.(*BGPUpdate)

		fmt.Printf("UPDATE Message:\n")
		fmt.Printf("Withdrawn routes:\n")
		for r := u.WithdrawnRoutes; r != nil; r = r.Next {
			x := r.IP.([4]byte)
			fmt.Printf("\t%s/%d\n", net.IP(x[:]).String(), r.Pfxlen)
		}

		fmt.Printf("Path attributes:\n")
		for a := u.PathAttributes; a != nil; a = a.Next {
			fmt.Printf("\tType:%d\n", a.TypeCode)
			fmt.Printf("\t:%v\n", a.Value)
		}

		fmt.Printf("NLRIs:\n")
		for n := u.NLRI; n != nil; n = n.Next {
			x := n.IP.([4]byte)
			fmt.Printf("\t%s/%d\n", net.IP(x[:]).String(), n.Pfxlen)
		}
	}
}
