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
		expected *node
	}{
		{
			name: "Insert first node",
			prefixes: []*net.Prefix{
				net.NewPfx(167772160, 8), // 10.0.0.0/8
			},
			expected: &node{
				pfx:  net.NewPfx(167772160, 8), // 10.0.0.0/8
				skip: 8,
			},
		},
		{
			name: "Insert double node",
			prefixes: []*net.Prefix{
				net.NewPfx(167772160, 8), // 10.0.0.0/8
				net.NewPfx(167772160, 8), // 10.0.0.0/8
				net.NewPfx(167772160, 8), // 10.0.0.0/8
				net.NewPfx(167772160, 8), // 10.0.0.0/8
			},
			expected: &node{
				pfx:  net.NewPfx(167772160, 8), // 10.0.0.0/8
				skip: 8,
			},
		},
		{
			name: "Insert triangle",
			prefixes: []*net.Prefix{
				net.NewPfx(167772160, 8), // 10.0.0.0
				net.NewPfx(167772160, 9), // 10.0.0.0
				net.NewPfx(176160768, 9), // 10.128.0.0
			},
			expected: &node{
				pfx:  net.NewPfx(167772160, 8), // 10.0.0.0/8
				skip: 8,
				l: &node{
					pfx: net.NewPfx(167772160, 9), // 10.0.0.0
				},
				h: &node{
					pfx: net.NewPfx(176160768, 9), // 10.128.0.0
				},
			},
		},
		{
			name: "Insert disjunct prefixes",
			prefixes: []*net.Prefix{
				net.NewPfx(167772160, 8),  // 10.0.0.0
				net.NewPfx(191134464, 24), // 11.100.123.0/24
			},
			expected: &node{
				pfx:   net.NewPfx(167772160, 7), // 10.0.0.0/7
				skip:  7,
				dummy: true,
				l: &node{
					pfx: net.NewPfx(167772160, 8), // 10.0.0.0/8
				},
				h: &node{
					pfx:  net.NewPfx(191134464, 24), // 10.0.0.0/8
					skip: 16,
				},
			},
		},
		{
			name: "Insert disjunct prefixes plus one child",
			prefixes: []*net.Prefix{
				net.NewPfx(167772160, 8),  // 10.0.0.0
				net.NewPfx(191134464, 24), // 11.100.123.0/24
				net.NewPfx(167772160, 12), // 10.0.0.0
				net.NewPfx(167772160, 10), // 10.0.0.0
			},
			expected: &node{
				pfx:   net.NewPfx(167772160, 7), // 10.0.0.0/7
				skip:  7,
				dummy: true,
				l: &node{
					pfx: net.NewPfx(167772160, 8), // 10.0.0.0/8
					l: &node{
						skip: 1,
						pfx:  net.NewPfx(167772160, 10), // 10.0.0.0/10
						l: &node{
							skip: 1,
							pfx:  net.NewPfx(167772160, 12), // 10.0.0.0
						},
					},
				},
				h: &node{
					pfx:  net.NewPfx(191134464, 24), // 10.0.0.0/8
					skip: 16,
				},
			},
		},
	}

	for _, test := range tests {
		l := New()
		for _, pfx := range test.prefixes {
			l.Insert(pfx)
		}

		assert.Equal(t, test.expected, l.root)
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
		{
			name:     "Test 2",
			prefixes: []*net.Prefix{},
			needle:   net.NewPfx(167772160, 32), // 10.0.0.0/32
			expected: nil,
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
		name          string
		moreSpecifics bool
		prefixes      []*net.Prefix
		needle        *net.Prefix
		expected      []*net.Prefix
	}{
		{
			name:          "Test 1",
			moreSpecifics: true,
			prefixes: []*net.Prefix{
				net.NewPfx(167772160, 8),  // 10.0.0.0/8
				net.NewPfx(191134464, 24), // 11.100.123.0/24
				net.NewPfx(167772160, 12), // 10.0.0.0/12
				net.NewPfx(167772160, 10), // 10.0.0.0/10
			},
			needle: net.NewPfx(167772160, 8), // 10.0.0.0/8
			expected: []*net.Prefix{
				net.NewPfx(167772160, 8),  // 10.0.0.0/8
				net.NewPfx(167772160, 10), // 10.0.0.0
				net.NewPfx(167772160, 12), // 10.0.0.0
			},
		},
		{
			name: "Test 2",
			prefixes: []*net.Prefix{
				net.NewPfx(167772160, 8),  // 10.0.0.0
				net.NewPfx(191134464, 24), // 11.100.123.0/24
				net.NewPfx(167772160, 12), // 10.0.0.0
				net.NewPfx(167772160, 10), // 10.0.0.0
			},
			needle: net.NewPfx(167772160, 8), // 10.0.0.0/8
			expected: []*net.Prefix{
				net.NewPfx(167772160, 8), // 10.0.0.0/8
			},
		},
		{
			name:     "Test 3",
			prefixes: []*net.Prefix{},
			needle:   net.NewPfx(167772160, 32), // 10.0.0.0/32
			expected: nil,
		},
		{
			name: "Test 4: Get Dummy",
			prefixes: []*net.Prefix{
				net.NewPfx(167772160, 8),  // 10.0.0.0
				net.NewPfx(191134464, 24), // 11.100.123.0/24
			},
			needle:   net.NewPfx(167772160, 7), // 10.0.0.0/7
			expected: nil,
		},
	}

	for _, test := range tests {
		lpm := New()
		for _, pfx := range test.prefixes {
			lpm.Insert(pfx)
		}
		p := lpm.Get(test.needle, test.moreSpecifics)

		if p == nil {
			if test.expected != nil {
				t.Errorf("Unexpected nil result for test %s", test.name)
			}
			continue
		}

		assert.Equal(t, test.expected, p)
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
		{
			name:     "test 3",
			input:    16777216,
			offset:   8,
			expected: true,
		},
	}

	for _, test := range tests {
		fmt.Println(strconv.FormatInt(int64(test.input), 2))
		b := getBitUint32(test.input, test.offset)
		if b != test.expected {
			t.Errorf("%s: Unexpected failure: Bit %d of %d is %v. Expected %v", test.name, test.offset, test.input, b, test.expected)
		}
	}
}

func TestInsertChildren(t *testing.T) {
	tests := []struct {
		name     string
		base     *net.Prefix
		old      *net.Prefix
		new      *net.Prefix
		expected *node
	}{
		{
			name: "Test 1",
			base: net.NewPfx(167772160, 8), //10.0.0.0/8
			old:  net.NewPfx(167772160, 9), //10.0.0.0/9
			new:  net.NewPfx(176160768, 9), //10.128.0.0/9
			expected: &node{
				pfx:   net.NewPfx(167772160, 8),
				skip:  8,
				dummy: true,
				l: &node{
					pfx: net.NewPfx(167772160, 9),
				},
				h: &node{
					pfx: net.NewPfx(176160768, 9),
				},
			},
		},
		{
			name: "Test 2",
			base: net.NewPfx(167772160, 8), //10.0.0.0/8
			old:  net.NewPfx(176160768, 9), //10.128.0.0/9
			new:  net.NewPfx(167772160, 9), //10.0.0.0/9
			expected: &node{
				pfx:   net.NewPfx(167772160, 8),
				skip:  8,
				dummy: true,
				l: &node{
					pfx: net.NewPfx(167772160, 9),
				},
				h: &node{
					pfx: net.NewPfx(176160768, 9),
				},
			},
		},
	}

	for _, test := range tests {
		n := newNode(test.base, test.base.Pfxlen(), true)
		old := newNode(test.old, test.old.Pfxlen(), false)
		n.insertChildren(old, test.new)
		assert.Equal(t, test.expected, n)
	}
}

func TestInsertBefore(t *testing.T) {
	tests := []struct {
		name     string
		a        *net.Prefix
		b        *net.Prefix
		expected *node
	}{
		{
			name: "Test 1",
			a:    net.NewPfx(167772160, 10), // 10.0.0.0
			b:    net.NewPfx(167772160, 8),  // 10.0.0.0
			expected: &node{
				pfx: net.NewPfx(167772160, 8), // 10.0.0.0,
				l: &node{
					pfx:  net.NewPfx(167772160, 10), // 10.0.0.0
					skip: 1,
				},
				skip: 1,
			},
		},
		{
			name: "Test 2",
			a:    net.NewPfx(184549376, 8), // 11.0.0.0/8
			b:    net.NewPfx(167772160, 7), // 10.0.0.0/7
			expected: &node{
				pfx: net.NewPfx(167772160, 7), // 10.0.0.0,
				h: &node{
					pfx:  net.NewPfx(184549376, 8), // 10.0.0.0
					skip: 0,
				},
				skip: 1,
			},
		},
	}

	for _, test := range tests {
		n := newNode(test.a, test.a.Pfxlen(), false)
		n = n.insertBefore(test.b, test.b.Pfxlen())
		assert.Equal(t, test.expected, n)
	}
}
