package lpm

import (
	"github.com/taktv6/tbgp/net"
)

type LPM struct {
	root  *node
	nodes uint64
}

type node struct {
	skip  uint8
	dummy bool
	pfx   *net.Prefix
	l     *node
	h     *node
}

// New creates a new empty LPM
func New() *LPM {
	return &LPM{}
}

func newNode(pfx *net.Prefix, skip uint8, dummy bool) *node {
	n := &node{
		pfx:   pfx,
		skip:  skip,
		dummy: dummy,
	}
	return n
}

// LPM performs a longest prefix match for pfx on lpm
func (lpm *LPM) LPM(pfx *net.Prefix) (res []*net.Prefix) {
	if lpm.root == nil {
		return nil
	}

	lpm.root.lpm(pfx, &res)
	return res
}

// Get get's prefix pfx from the LPM
func (lpm *LPM) Get(pfx *net.Prefix, moreSpecifics bool) (res []*net.Prefix) {
	if lpm.root == nil {
		return nil
	}

	node := lpm.root.get(pfx)
	if moreSpecifics {
		return node.dumpPfxs(res)
	}

	if node == nil {
		return nil
	}

	return []*net.Prefix{
		node.pfx,
	}
}

// Insert inserts a route into the LPM
func (lpm *LPM) Insert(pfx *net.Prefix) {
	if lpm.root == nil {
		lpm.root = newNode(pfx, pfx.Pfxlen(), false)
		return
	}

	lpm.root = lpm.root.insert(pfx)
}

func (n *node) lpm(needle *net.Prefix, res *[]*net.Prefix) {
	if n == nil {
		return
	}

	if *n.pfx == *needle && !n.dummy {
		*res = append(*res, n.pfx)
		return
	}

	if !n.pfx.Contains(needle) {
		return
	}

	if !n.dummy {
		*res = append(*res, n.pfx)
	}
	n.l.lpm(needle, res)
	n.h.lpm(needle, res)
}

func (n *node) dumpPfxs(res []*net.Prefix) []*net.Prefix {
	if n == nil {
		return nil
	}

	if !n.dummy {
		res = append(res, n.pfx)
	}

	if n.l != nil {
		res = n.l.dumpPfxs(res)
	}

	if n.h != nil {
		res = n.h.dumpPfxs(res)
	}

	return res
}

func (n *node) get(pfx *net.Prefix) *node {
	if n == nil {
		return nil
	}

	if *n.pfx == *pfx {
		if n.dummy {
			return nil
		}
		return n
	}

	if n.pfx.Pfxlen() > pfx.Pfxlen() {
		return nil
	}

	b := getBitUint32(pfx.Addr(), n.pfx.Pfxlen()+1)
	if !b {
		return n.l.get(pfx)
	}
	return n.h.get(pfx)
}

func (n *node) insert(pfx *net.Prefix) *node {
	if *n.pfx == *pfx {
		return n
	}

	// is pfx NOT a subnet of this node?
	if !n.pfx.Contains(pfx) {
		if pfx.Contains(n.pfx) {
			return n.insertBefore(pfx, n.pfx.Pfxlen()-n.skip-1)
		}

		return n.newSuperNode(pfx)
	}

	// pfx is a subnet of this node
	b := getBitUint32(pfx.Addr(), n.pfx.Pfxlen()+1)
	if !b {
		return n.insertLow(pfx, n.pfx.Pfxlen())
	}
	return n.insertHigh(pfx, n.pfx.Pfxlen())
}

func (n *node) insertLow(pfx *net.Prefix, parentPfxLen uint8) *node {
	if n.l == nil {
		n.l = newNode(pfx, pfx.Pfxlen()-parentPfxLen-1, false)
		return n
	}
	n.l = n.l.insert(pfx)
	return n
}

func (n *node) insertHigh(pfx *net.Prefix, parentPfxLen uint8) *node {
	if n.h == nil {
		n.h = newNode(pfx, pfx.Pfxlen()-parentPfxLen-1, false)
		return n
	}
	n.h = n.h.insert(pfx)
	return n
}

func (n *node) newSuperNode(pfx *net.Prefix) *node {
	superNet := pfx.GetSupernet(n.pfx)

	pfxLenDiff := n.pfx.Pfxlen() - superNet.Pfxlen()
	skip := n.skip - pfxLenDiff

	pseudoNode := newNode(superNet, skip, true)
	pseudoNode.insertChildren(n, pfx)
	return pseudoNode
}

func (n *node) insertChildren(old *node, new *net.Prefix) {
	// Place the old node
	b := getBitUint32(old.pfx.Addr(), n.pfx.Pfxlen()+1)
	if !b {
		n.l = old
		n.l.skip = old.pfx.Pfxlen() - n.pfx.Pfxlen() - 1
	} else {
		n.h = old
		n.h.skip = old.pfx.Pfxlen() - n.pfx.Pfxlen() - 1
	}

	// Place the new Prefix
	newNode := newNode(new, new.Pfxlen()-n.pfx.Pfxlen()-1, false)
	b = getBitUint32(new.Addr(), n.pfx.Pfxlen()+1)
	if !b {
		n.l = newNode
	} else {
		n.h = newNode
	}
}

func (n *node) insertBefore(pfx *net.Prefix, parentPfxLen uint8) *node {
	tmp := n

	pfxLenDiff := n.pfx.Pfxlen() - pfx.Pfxlen()
	skip := n.skip - pfxLenDiff
	new := newNode(pfx, skip, false)

	b := getBitUint32(pfx.Addr(), parentPfxLen) // TODO: Is this correct?
	if !b {
		new.l = tmp
		new.l.skip = tmp.pfx.Pfxlen() - pfx.Pfxlen() - 1
	} else {
		new.h = tmp
		new.h.skip = tmp.pfx.Pfxlen() - pfx.Pfxlen() - 1
	}

	return new
}

func getBitUint32(x uint32, pos uint8) bool {
	return ((x) & (1 << (32 - pos))) != 0
}
