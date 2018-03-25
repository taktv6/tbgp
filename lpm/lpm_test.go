package lpm

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/taktv6/tbgp/net"

	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	l := New()
	if l == nil {
		t.Errorf("New() returned nil")
	}
}

func TestInsert(t *testing.T) {
	tests := []struct {
		name     string
		prefixes []*net.Prefix
		wantFail bool
		//expected uint32
	}{
		{
			name: "Insert first node",
			prefixes: []*net.Prefix{
				net.NewPfx(167772160, 8), // 10.0.0.0/8
				net.NewPfx(0, 0),         // 0.0.0.0/0
			},
			wantFail: false,
			//expected: 100,
		},
		{
			name: "Insert first node",
			prefixes: []*net.Prefix{
				net.NewPfx(167772160, 8), // 10.0.0.0/8
				net.NewPfx(0, 0),         // 0.0.0.0/0

			},
			wantFail: false,
			//expected: 100,
		},
		{
			name: "Insert first node",
			prefixes: []*net.Prefix{
				net.NewPfx(167772160, 8), // 10.0.0.0
				net.NewPfx(134217728, 5), // 8.0.0.0
				net.NewPfx(268435456, 5), // 16.0.0.0
			},
			wantFail: false,
			//expected: 100,
		},
		{
			name: "Insert first node",
			prefixes: []*net.Prefix{
				net.NewPfx(167772160, 8), // 10.0.0.0
				net.NewPfx(184549376, 8), // 11.0.0.0
			},
			wantFail: false,
			//expected: 100,
		},
		{
			name: "Insert disjunct prefixes",
			prefixes: []*net.Prefix{
				net.NewPfx(167772160, 8),  // 10.0.0.0
				net.NewPfx(191134464, 24), // 11.100.123.0/24
			},
			wantFail: false,
			//expected: 100,
		},
		{
			name: "Insert disjunct prefixes plus one child",
			prefixes: []*net.Prefix{
				net.NewPfx(167772160, 8),  // 10.0.0.0
				net.NewPfx(191134464, 24), // 11.100.123.0/24
				net.NewPfx(167772160, 12), // 10.0.0.0
				net.NewPfx(167772160, 10), // 10.0.0.0
			},
			wantFail: false,
			//expected: 100,
		},
	}

	for _, test := range tests {
		fmt.Printf("\nTest: %s\n", test.name)
		l := New()
		for _, pfx := range test.prefixes {
			l.Insert(pfx)
		}

		l.root.dump()
		fmt.Printf("\n-----------------------------\n\n")

		//if l.root.key != test.expected {
		//t.Errorf("Test %s failed: ")
		//}
	}
}

func TestLPM(t *testing.T) {
	tests := []struct {
		name     string
		prefixes []*net.Prefix
		needle   *net.Prefix
		expected []*net.Prefix
	}{
		{
			name: "Test 1",
			prefixes: []*net.Prefix{
				net.NewPfx(167772160, 8),  // 10.0.0.0
				net.NewPfx(191134464, 24), // 11.100.123.0/24
				net.NewPfx(167772160, 12), // 10.0.0.0
				net.NewPfx(167772160, 10), // 10.0.0.0
			},
			needle: net.NewPfx(167772160, 32), // 10.0.0.0/32
			expected: []*net.Prefix{
				net.NewPfx(167772160, 8),  // 10.0.0.0
				net.NewPfx(167772160, 10), // 10.0.0.0
				net.NewPfx(167772160, 12), // 10.0.0.0
			},
		},
	}

	for _, test := range tests {
		lpm := New()
		for _, pfx := range test.prefixes {
			lpm.Insert(pfx)
		}
		assert.Equal(t, test.expected, lpm.LPM(test.needle))
	}
}

func TestGet(t *testing.T) {
	tests := []struct {
		name     string
		prefixes []*net.Prefix
		needle   *net.Prefix
		expected *net.Prefix
	}{
		{
			name: "Test 1",
			prefixes: []*net.Prefix{
				net.NewPfx(167772160, 8),  // 10.0.0.0
				net.NewPfx(191134464, 24), // 11.100.123.0/24
				net.NewPfx(167772160, 12), // 10.0.0.0
				net.NewPfx(167772160, 10), // 10.0.0.0
			},
			needle:   net.NewPfx(167772160, 8), // 10.0.0.0/8
			expected: net.NewPfx(167772160, 8), // 10.0.0.0/8
		},
	}

	for _, test := range tests {
		lpm := New()
		for _, pfx := range test.prefixes {
			lpm.Insert(pfx)
		}
		p := lpm.Get(test.needle, false)
		if p == nil && test.expected != nil {
			t.Errorf("Test %s: Unexpected nil result: Expected %s\n", test.name, test.expected.String())
		}

		assert.Equal(t, test.expected.String(), p[0].String())
	}
}

func TestNewSuperNode(t *testing.T) {
	tests := []struct {
		name     string
		a        *net.Prefix
		b        *net.Prefix
		expected *node
	}{
		{
			name: "Test 1",
			a:    net.NewPfx(167772160, 8),  // 10.0.0.0
			b:    net.NewPfx(191134464, 24), // 11.100.123.0/24
			expected: &node{
				pfx:   net.NewPfx(167772160, 7), // 10.0.0.0
				skip:  7,
				dummy: true,
				l: &node{
					pfx: net.NewPfx(167772160, 8), // 10.0.0.0
				},
				h: &node{
					pfx:  net.NewPfx(191134464, 24), //11.100.123.0/24
					skip: 16,
				},
			},
		},
	}

	for _, test := range tests {
		n := newNode(test.a, test.a.Pfxlen(), false)
		n = n.newSuperNode(test.b)
		assert.Equal(t, test.expected, n)
	}
}

func TestGetBitUint32(t *testing.T) {
	tests := []struct {
		name     string
		input    uint32
		offset   uint8
		expected bool
	}{
		/*{
			name:     "test 1",
			input:    128,
			offset:   7,
			expected: true,
		},
		{
			name:     "test 2",
			input:    128,
			offset:   8,
			expected: false,
		},*/
		{
			name:     "test 3",
			input:    16777216,
			offset:   8,
			expected: true,
		},
	}

	for _, test := range tests {
		fmt.Println(strconv.FormatInt(int64(test.input), 2))
		/*for i := 0; i < 32; i++ {
			fmt.Printf("%d = %v\n", i, getBitUint32(test.input, uint8(i)))
		}*/
		b := getBitUint32(test.input, test.offset)
		if b != test.expected {
			t.Errorf("%s: Unexpected failure: Bit %d of %d is %v. Expected %v", test.name, test.offset, test.input, b, test.expected)
		}
	}
}
