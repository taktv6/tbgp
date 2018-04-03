package packet

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecodePathAttr(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		wantFail bool
		expected *PathAttribute
	}{
		{
			name: "",
			input: []byte{
				0, // Attr. Flags
				1, // Attr. Type Code
				1, // Attr. Length
				1, // EGP
			},
			wantFail: false,
			expected: &PathAttribute{
				Length:         1,
				Optional:       false,
				Transitive:     false,
				Partial:        false,
				ExtendedLength: false,
				TypeCode:       OriginAttr,
				Value:          uint8(1),
			},
		},
	}

	for _, test := range tests {
		res, _, err := decodePathAttr(bytes.NewBuffer(test.input))

		if test.wantFail && err == nil {
			t.Errorf("Expected error did not happen for test %q", test.name)
		}

		if !test.wantFail && err != nil {
			t.Errorf("Unexpected failure for test %q: %v", test.name, err)
		}

		assert.Equal(t, test.expected, res)
	}
}

func TestDecodeLocalPref(t *testing.T) {
	tests := []struct {
		name           string
		input          []byte
		wantFail       bool
		explicitLength uint16
		expected       *PathAttribute
	}{
		{
			name: "Test #1",
			input: []byte{
				0, 0, 3, 232,
			},
			wantFail: false,
			expected: &PathAttribute{
				Length: 4,
				Value:  uint32(1000),
			},
		},
		{
			name:           "Test #2",
			input:          []byte{},
			explicitLength: 5,
			wantFail:       true,
		},
	}

	for _, test := range tests {
		l := uint16(len(test.input))
		if test.explicitLength != 0 {
			l = test.explicitLength
		}
		pa := &PathAttribute{
			Length: l,
		}
		err := pa.decodeLocalPref(bytes.NewBuffer(test.input))

		if test.wantFail && err == nil {
			t.Errorf("Expected error did not happen for test %q", test.name)
		}

		if !test.wantFail && err != nil {
			t.Errorf("Unexpected failure for test %q: %v", test.name, err)
		}

		if err != nil {
			continue
		}

		assert.Equal(t, test.expected, pa)
	}
}

func TestDecodeMED(t *testing.T) {
	tests := []struct {
		name           string
		input          []byte
		wantFail       bool
		explicitLength uint16
		expected       *PathAttribute
	}{
		{
			name: "Test #1",
			input: []byte{
				0, 0, 3, 232,
			},
			wantFail: false,
			expected: &PathAttribute{
				Length: 4,
				Value:  uint32(1000),
			},
		},
		{
			name:           "Test #2",
			input:          []byte{},
			explicitLength: 5,
			wantFail:       true,
		},
	}

	for _, test := range tests {
		l := uint16(len(test.input))
		if test.explicitLength != 0 {
			l = test.explicitLength
		}
		pa := &PathAttribute{
			Length: l,
		}
		err := pa.decodeMED(bytes.NewBuffer(test.input))

		if test.wantFail && err == nil {
			t.Errorf("Expected error did not happen for test %q", test.name)
		}

		if !test.wantFail && err != nil {
			t.Errorf("Unexpected failure for test %q: %v", test.name, err)
		}

		if err != nil {
			continue
		}

		assert.Equal(t, test.expected, pa)
	}
}

func TestDecodeNextHop(t *testing.T) {
	tests := []struct {
		name           string
		input          []byte
		wantFail       bool
		explicitLength uint16
		expected       *PathAttribute
	}{
		{
			name: "Test #1",
			input: []byte{
				10, 20, 30, 40,
			},
			wantFail: false,
			expected: &PathAttribute{
				Length: 4,
				Value: [4]byte{
					10, 20, 30, 40,
				},
			},
		},
		{
			name:           "Test #2",
			input:          []byte{},
			explicitLength: 5,
			wantFail:       true,
		},
	}

	for _, test := range tests {
		l := uint16(len(test.input))
		if test.explicitLength != 0 {
			l = test.explicitLength
		}
		pa := &PathAttribute{
			Length: l,
		}
		err := pa.decodeNextHop(bytes.NewBuffer(test.input))

		if test.wantFail && err == nil {
			t.Errorf("Expected error did not happen for test %q", test.name)
		}

		if !test.wantFail && err != nil {
			t.Errorf("Unexpected failure for test %q: %v", test.name, err)
		}

		if err != nil {
			continue
		}

		assert.Equal(t, test.expected, pa)
	}
}

func TestDecodeASPath(t *testing.T) {
	tests := []struct {
		name           string
		input          []byte
		wantFail       bool
		explicitLength uint16
		expected       *PathAttribute
	}{
		{
			name: "Test #1",
			input: []byte{
				2, // AS_SEQUENCE
				4, // Path Length
				0, 100, 0, 200, 0, 222, 0, 240,
			},
			wantFail: false,
			expected: &PathAttribute{
				Length: 10,
				Value: ASPath{
					ASPathSegment{
						Type:  2,
						Count: 4,
						ASNs: []uint32{
							100, 200, 222, 240,
						},
					},
				},
			},
		},
		{
			name: "Test #2",
			input: []byte{
				1, // AS_SEQUENCE
				3, // Path Length
				0, 100, 0, 222, 0, 240,
			},
			wantFail: false,
			expected: &PathAttribute{
				Length: 8,
				Value: ASPath{
					ASPathSegment{
						Type:  1,
						Count: 3,
						ASNs: []uint32{
							100, 222, 240,
						},
					},
				},
			},
		},
		{
			name:           "Test #3",
			input:          []byte{},
			explicitLength: 5,
			wantFail:       true,
		},
	}

	for _, test := range tests {
		l := uint16(len(test.input))
		if test.explicitLength != 0 {
			l = test.explicitLength
		}
		pa := &PathAttribute{
			Length: l,
		}
		err := pa.decodeASPath(bytes.NewBuffer(test.input))

		if test.wantFail && err == nil {
			t.Errorf("Expected error did not happen for test %q", test.name)
		}

		if !test.wantFail && err != nil {
			t.Errorf("Unexpected failure for test %q: %v", test.name, err)
		}

		if err != nil {
			continue
		}

		assert.Equal(t, test.expected, pa)
	}
}

func TestDecodeOrigin(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		wantFail bool
		expected *PathAttribute
	}{
		{
			name: "Test #1",
			input: []byte{
				0, // Origin: IGP
			},
			wantFail: false,
			expected: &PathAttribute{
				Value:  uint8(IGP),
				Length: 1,
			},
		},
		{
			name: "Test #2",
			input: []byte{
				1, // Origin: EGP
			},
			wantFail: false,
			expected: &PathAttribute{
				Value:  uint8(EGP),
				Length: 1,
			},
		},
		{
			name: "Test #3",
			input: []byte{
				2, // Origin: INCOMPLETE
			},
			wantFail: false,
			expected: &PathAttribute{
				Value:  uint8(INCOMPLETE),
				Length: 1,
			},
		},
		{
			name:     "Test #4",
			input:    []byte{},
			wantFail: true,
		},
	}

	for _, test := range tests {
		pa := &PathAttribute{
			Length: uint16(len(test.input)),
		}
		err := pa.decodeOrigin(bytes.NewBuffer(test.input))

		if test.wantFail && err == nil {
			t.Errorf("Expected error did not happen for test %q", test.name)
		}

		if !test.wantFail && err != nil {
			t.Errorf("Unexpected failure for test %q: %v", test.name, err)
		}

		if err != nil {
			continue
		}

		assert.Equal(t, test.expected, pa)
	}
}
