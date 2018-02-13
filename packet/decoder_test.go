package packet

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type test struct {
	testNum  int
	input    []byte
	wantFail bool
	expected interface{}
}

type decodeFunc func(*bytes.Buffer) (interface{}, error)

func BenchmarkDecodeUpdateMsg(b *testing.B) {
	input := []byte{0, 5, 8, 10, 16, 192, 168,
		0, 53, // Total Path Attribute Length

		255,  // Attribute flags
		1,    // Attribute Type code (ORIGIN)
		0, 1, // Length
		2, // INCOMPLETE

		0,      // Attribute flags
		2,      // Attribute Type code (AS Path)
		12,     // Length
		2,      // Type = AS_SEQUENCE
		2,      // Path Segement Length
		59, 65, // AS15169
		12, 248, // AS3320
		1,      // Type = AS_SET
		2,      // Path Segement Length
		59, 65, // AS15169
		12, 248, // AS3320

		0,              // Attribute flags
		3,              // Attribute Type code (Next Hop)
		4,              // Length
		10, 11, 12, 13, // Next Hop

		0,          // Attribute flags
		4,          // Attribute Type code (MED)
		4,          // Length
		0, 0, 1, 0, // MED 256

		0,          // Attribute flags
		5,          // Attribute Type code (Local Pref)
		4,          // Length
		0, 0, 1, 0, // Local Pref 256

		0, // Attribute flags
		6, // Attribute Type code (Atomic Aggregate)
		0, // Length

		0,    // Attribute flags
		7,    // Attribute Type code (Atomic Aggregate)
		6,    // Length
		1, 2, // ASN
		10, 11, 12, 13, // Address

		8, 11, // 11.0.0.0/8
	}

	for i := 0; i < b.N; i++ {
		buf := bytes.NewBuffer(input)
		_, err := decodeUpdateMsg(buf, MsgLength(len(input)))
		if err != nil {
			fmt.Printf("decodeUpdateMsg failed: %v\n", err)
		}
		//buf.Next(1)
	}
}

func TestDecode(t *testing.T) {
	tests := []test{
		{
			// Proper packet
			testNum: 1,
			input: []byte{
				1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // Marker
				0, 19, // Length
				4, // Type = Keepalive

			},
			wantFail: false,
			expected: BGPMessage{
				Header: &BGPHeader{
					Length: 19,
					Type:   4,
				},
			},
		},
		{
			// Invalid marker
			testNum: 2,
			input: []byte{
				1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, // Marker
				0, 19, // Length
				4, // Type = Keepalive

			},
			wantFail: true,
			expected: BGPMessage{
				Header: &BGPHeader{
					Length: 19,
					Type:   4,
				},
			},
		},
		{
			// Proper NOTIFICATION packet
			testNum: 3,
			input: []byte{
				1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // Marker
				0, 21, // Length
				3,    // Type = Notification
				1, 1, // Message Header Error, Connection Not Synchronized.
			},
			wantFail: false,
			expected: BGPMessage{
				Header: &BGPHeader{
					Length: 21,
					Type:   3,
				},
				Body: BGPNotification{
					ErrorCode:    1,
					ErrorSubcode: 1,
				},
			},
		},
		{
			// Proper OPEN packet
			testNum: 4,
			input: []byte{
				1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // Marker
				0, 29, // Length
				1,      // Type = Open
				4,      // Version
				0, 200, //ASN,
				0, 15, // Holdtime
				0, 0, 0, 100, // BGP Identifier
				0, // Opt Parm Len
			},
			wantFail: false,
			expected: BGPMessage{
				Header: &BGPHeader{
					Length: 29,
					Type:   1,
				},
				Body: BGPOpen{
					Version:       4,
					AS:            200,
					HoldTime:      15,
					BGPIdentifier: BGPIdentifier(100),
					OptParmLen:    0,
				},
			},
		},
		{
			// Incomplete OPEN packet
			testNum: 5,
			input: []byte{
				1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // Marker
				0, 28, // Length
				1,      // Type = Open
				4,      // Version
				0, 200, //ASN,
				0, 15, // Holdtime
				0, 0, 0, 100, // BGP Identifier
			},
			wantFail: true,
			expected: BGPMessage{
				Header: &BGPHeader{
					Length: 28,
					Type:   1,
				},
				Body: BGPOpen{
					Version:       4,
					AS:            200,
					HoldTime:      15,
					BGPIdentifier: BGPIdentifier(100),
				},
			},
		},
	}

	for _, test := range tests {
		buf := bytes.NewBuffer(test.input)
		msg, err := Decode(buf)

		if err != nil && !test.wantFail {
			t.Errorf("Unexpected error in test %d: %v", test.testNum, err)
			continue
		}

		if err == nil && test.wantFail {
			t.Errorf("Expected error did not happen in test %d", test.testNum)
			continue
		}

		if err != nil && test.wantFail {
			continue
		}

		if msg == nil {
			t.Errorf("Unexpected nil result in test %d. Expected: %v", test.testNum, test.expected)
			continue
		}

		assert.Equal(t, test.expected, *msg)
	}
}

func TestDecodeNotificationMsg(t *testing.T) {
	tests := []test{
		{
			// Invalid ErrCode
			testNum:  1,
			input:    []byte{0, 0},
			wantFail: true,
		},
		{
			// Invalid ErrCode
			testNum:  2,
			input:    []byte{7, 0},
			wantFail: true,
		},
		{
			// Invalid ErrSubCode (Header)
			testNum:  3,
			input:    []byte{1, 0},
			wantFail: true,
		},
		{
			// Invalid ErrSubCode (Header)
			testNum:  4,
			input:    []byte{1, 4},
			wantFail: true,
		},
		{
			// Invalid ErrSubCode (Open)
			testNum:  5,
			input:    []byte{2, 0},
			wantFail: true,
		},
		{
			// Invalid ErrSubCode (Open)
			testNum:  6,
			input:    []byte{2, 7},
			wantFail: true,
		},
		{
			// Invalid ErrSubCode (Open)
			testNum:  7,
			input:    []byte{2, 5},
			wantFail: true,
		},
		{
			// Invalid ErrSubCode (Update)
			testNum:  8,
			input:    []byte{3, 0},
			wantFail: true,
		},
		{
			// Invalid ErrSubCode (Update)
			testNum:  9,
			input:    []byte{3, 12},
			wantFail: true,
		},
		{
			// Invalid ErrSubCode (Update)
			testNum:  10,
			input:    []byte{3, 7},
			wantFail: true,
		},
		{
			// Valid notification
			testNum:  11,
			input:    []byte{2, 2},
			wantFail: false,
			expected: BGPNotification{
				ErrorCode:    2,
				ErrorSubcode: 2,
			},
		},
	}

	genericTest(_decodeNotificationMsg, tests, t)
}

func TestDecodeUpdateMsg(t *testing.T) {
	tests := []test{
		{
			// 2 withdraws only, valid update
			testNum:  1,
			input:    []byte{0, 5, 8, 10, 16, 192, 168, 0, 0},
			wantFail: false,
			expected: BGPUpdate{
				WithdrawnRoutesLen: 5,
				WithdrawnRoutes: []NLRI{
					{
						IP:     IPv4Addr{10, 0, 0, 0},
						Pfxlen: 8,
					},
					{
						IP:     IPv4Addr{192, 168, 0, 0},
						Pfxlen: 16,
					},
				},
				PathAttributes: []PathAttribute{},
			},
		},
		{
			// 2 withdraws with one path attribute (ORIGIN), valid update
			testNum: 2,
			input: []byte{0, 5, 8, 10, 16, 192, 168,
				0, 5, // Total Path Attribute Length
				255,  // Attribute flags
				1,    // Attribute Type code
				0, 1, // Length
				2, // INCOMPLETE
			},
			wantFail: false,
			expected: BGPUpdate{
				WithdrawnRoutesLen: 5,
				WithdrawnRoutes: []NLRI{
					{
						IP:     IPv4Addr{10, 0, 0, 0},
						Pfxlen: 8,
					},
					{
						IP:     IPv4Addr{192, 168, 0, 0},
						Pfxlen: 16,
					},
				},
				TotalPathAttrLen: 5,
				PathAttributes: []PathAttribute{
					{
						Optional:       true,
						Transitive:     true,
						Partial:        true,
						ExtendedLength: true,
						Length:         1,
						TypeCode:       1,
						Value:          Origin(2),
					},
				},
			},
		},
		{
			// 2 withdraws with two path attributes (ORIGIN + ASPath), valid update
			testNum: 3,
			input: []byte{0, 5, 8, 10, 16, 192, 168,
				0, 14, // Total Path Attribute Length

				255,  // Attribute flags
				1,    // Attribute Type code (ORIGIN)
				0, 1, // Length
				2, // INCOMPLETE

				0,      // Attribute flags
				2,      // Attribute Type code (AS Path)
				6,      // Length
				2,      // Type = AS_SEQUENCE
				2,      // Path Segement Length
				59, 65, // AS15169
				12, 248, // AS3320
			},
			wantFail: false,
			expected: BGPUpdate{
				WithdrawnRoutesLen: 5,
				WithdrawnRoutes: []NLRI{
					{
						IP:     IPv4Addr{10, 0, 0, 0},
						Pfxlen: 8,
					},
					{
						IP:     IPv4Addr{192, 168, 0, 0},
						Pfxlen: 16,
					},
				},
				TotalPathAttrLen: 14,
				PathAttributes: []PathAttribute{
					{
						Optional:       true,
						Transitive:     true,
						Partial:        true,
						ExtendedLength: true,
						Length:         1,
						TypeCode:       1,
						Value:          Origin(2),
					},
					{
						Optional:       false,
						Transitive:     false,
						Partial:        false,
						ExtendedLength: false,
						Length:         6,
						TypeCode:       2,
						Value: ASPath{
							{
								Type:  2,
								Count: 2,
								ASNs: []ASN32{
									15169,
									3320,
								},
							},
						},
					},
				},
			},
		},
		{
			// 2 withdraws with two path attributes (ORIGIN + ASPath), invalid AS Path segment type
			testNum: 4,
			input: []byte{0, 5, 8, 10, 16, 192, 168,
				0, 13, // Total Path Attribute Length

				255,  // Attribute flags
				1,    // Attribute Type code (ORIGIN)
				0, 1, // Length
				2, // INCOMPLETE

				0, // Attribute flags
				2, // Attribute Type code (AS Path)
				6, // Length
				1, // Type = AS_SET
				0, // Path Segement Length
			},
			wantFail: true,
		},
		{
			// 2 withdraws with two path attributes (ORIGIN + ASPath), invalid AS Path segment member count
			testNum: 5,
			input: []byte{0, 5, 8, 10, 16, 192, 168,
				0, 13, // Total Path Attribute Length

				255,  // Attribute flags
				1,    // Attribute Type code (ORIGIN)
				0, 1, // Length
				2, // INCOMPLETE

				0,      // Attribute flags
				2,      // Attribute Type code (AS Path)
				6,      // Length
				3,      // Type = INVALID
				2,      // Path Segement Length
				59, 65, // AS15169
				12, 248, // AS3320
			},
			wantFail: true,
		},
		{
			// 2 withdraws with two path attributes (ORIGIN + ASPath), valid update
			testNum: 6,
			input: []byte{0, 5, 8, 10, 16, 192, 168,
				0, 20, // Total Path Attribute Length

				255,  // Attribute flags
				1,    // Attribute Type code (ORIGIN)
				0, 1, // Length
				2, // INCOMPLETE

				0,      // Attribute flags
				2,      // Attribute Type code (AS Path)
				12,     // Length
				2,      // Type = AS_SEQUENCE
				2,      // Path Segement Length
				59, 65, // AS15169
				12, 248, // AS3320
				1,      // Type = AS_SET
				2,      // Path Segement Length
				59, 65, // AS15169
				12, 248, // AS3320
			},
			wantFail: false,
			expected: BGPUpdate{
				WithdrawnRoutesLen: 5,
				WithdrawnRoutes: []NLRI{
					{
						IP:     IPv4Addr{10, 0, 0, 0},
						Pfxlen: 8,
					},
					{
						IP:     IPv4Addr{192, 168, 0, 0},
						Pfxlen: 16,
					},
				},
				TotalPathAttrLen: 20,
				PathAttributes: []PathAttribute{
					{
						Optional:       true,
						Transitive:     true,
						Partial:        true,
						ExtendedLength: true,
						Length:         1,
						TypeCode:       1,
						Value:          Origin(2),
					},
					{
						Optional:       false,
						Transitive:     false,
						Partial:        false,
						ExtendedLength: false,
						Length:         12,
						TypeCode:       2,
						Value: ASPath{
							{
								Type:  2,
								Count: 2,
								ASNs: []ASN32{
									15169,
									3320,
								},
							},
							{
								Type:  1,
								Count: 2,
								ASNs: []ASN32{
									15169,
									3320,
								},
							},
						},
					},
				},
			},
		},
		{
			// 2 withdraws with 3 path attributes (ORIGIN + ASPath, NH), valid update
			testNum: 7,
			input: []byte{0, 5, 8, 10, 16, 192, 168,
				0, 27, // Total Path Attribute Length

				255,  // Attribute flags
				1,    // Attribute Type code (ORIGIN)
				0, 1, // Length
				2, // INCOMPLETE

				0,      // Attribute flags
				2,      // Attribute Type code (AS Path)
				12,     // Length
				2,      // Type = AS_SEQUENCE
				2,      // Path Segement Length
				59, 65, // AS15169
				12, 248, // AS3320
				1,      // Type = AS_SET
				2,      // Path Segement Length
				59, 65, // AS15169
				12, 248, // AS3320

				0,              // Attribute flags
				3,              // Attribute Type code (Next Hop)
				4,              // Length
				10, 11, 12, 13, // Next Hop

			},
			wantFail: false,
			expected: BGPUpdate{
				WithdrawnRoutesLen: 5,
				WithdrawnRoutes: []NLRI{
					{
						IP:     IPv4Addr{10, 0, 0, 0},
						Pfxlen: 8,
					},
					{
						IP:     IPv4Addr{192, 168, 0, 0},
						Pfxlen: 16,
					},
				},
				TotalPathAttrLen: 27,
				PathAttributes: []PathAttribute{
					{
						Optional:       true,
						Transitive:     true,
						Partial:        true,
						ExtendedLength: true,
						Length:         1,
						TypeCode:       1,
						Value:          Origin(2),
					},
					{
						Optional:       false,
						Transitive:     false,
						Partial:        false,
						ExtendedLength: false,
						Length:         12,
						TypeCode:       2,
						Value: ASPath{
							{
								Type:  2,
								Count: 2,
								ASNs: []ASN32{
									15169,
									3320,
								},
							},
							{
								Type:  1,
								Count: 2,
								ASNs: []ASN32{
									15169,
									3320,
								},
							},
						},
					},
					{
						Optional:       false,
						Transitive:     false,
						Partial:        false,
						ExtendedLength: false,
						Length:         4,
						TypeCode:       3,
						Value:          IPv4Addr{10, 11, 12, 13},
					},
				},
			},
		},
		{
			// 2 withdraws with 4 path attributes (ORIGIN + ASPath, NH, MED), valid update
			testNum: 8,
			input: []byte{0, 5, 8, 10, 16, 192, 168,
				0, 34, // Total Path Attribute Length

				255,  // Attribute flags
				1,    // Attribute Type code (ORIGIN)
				0, 1, // Length
				2, // INCOMPLETE

				0,      // Attribute flags
				2,      // Attribute Type code (AS Path)
				12,     // Length
				2,      // Type = AS_SEQUENCE
				2,      // Path Segement Length
				59, 65, // AS15169
				12, 248, // AS3320
				1,      // Type = AS_SET
				2,      // Path Segement Length
				59, 65, // AS15169
				12, 248, // AS3320

				0,              // Attribute flags
				3,              // Attribute Type code (Next Hop)
				4,              // Length
				10, 11, 12, 13, // Next Hop

				0,          // Attribute flags
				4,          // Attribute Type code (Next Hop)
				4,          // Length
				0, 0, 1, 0, // MED 256

			},
			wantFail: false,
			expected: BGPUpdate{
				WithdrawnRoutesLen: 5,
				WithdrawnRoutes: []NLRI{
					{
						IP:     IPv4Addr{10, 0, 0, 0},
						Pfxlen: 8,
					},
					{
						IP:     IPv4Addr{192, 168, 0, 0},
						Pfxlen: 16,
					},
				},
				TotalPathAttrLen: 34,
				PathAttributes: []PathAttribute{
					{
						Optional:       true,
						Transitive:     true,
						Partial:        true,
						ExtendedLength: true,
						Length:         1,
						TypeCode:       1,
						Value:          Origin(2),
					},
					{
						Optional:       false,
						Transitive:     false,
						Partial:        false,
						ExtendedLength: false,
						Length:         12,
						TypeCode:       2,
						Value: ASPath{
							{
								Type:  2,
								Count: 2,
								ASNs: []ASN32{
									15169,
									3320,
								},
							},
							{
								Type:  1,
								Count: 2,
								ASNs: []ASN32{
									15169,
									3320,
								},
							},
						},
					},
					{
						Optional:       false,
						Transitive:     false,
						Partial:        false,
						ExtendedLength: false,
						Length:         4,
						TypeCode:       3,
						Value:          IPv4Addr{10, 11, 12, 13},
					},
					{
						Optional:       false,
						Transitive:     false,
						Partial:        false,
						ExtendedLength: false,
						Length:         4,
						TypeCode:       4,
						Value:          MED(256),
					},
				},
			},
		},
		{
			// 2 withdraws with 4 path attributes (ORIGIN + ASPath, NH, MED, Local Pref), valid update
			testNum: 9,
			input: []byte{0, 5, 8, 10, 16, 192, 168,
				0, 41, // Total Path Attribute Length

				255,  // Attribute flags
				1,    // Attribute Type code (ORIGIN)
				0, 1, // Length
				2, // INCOMPLETE

				0,      // Attribute flags
				2,      // Attribute Type code (AS Path)
				12,     // Length
				2,      // Type = AS_SEQUENCE
				2,      // Path Segement Length
				59, 65, // AS15169
				12, 248, // AS3320
				1,      // Type = AS_SET
				2,      // Path Segement Length
				59, 65, // AS15169
				12, 248, // AS3320

				0,              // Attribute flags
				3,              // Attribute Type code (Next Hop)
				4,              // Length
				10, 11, 12, 13, // Next Hop

				0,          // Attribute flags
				4,          // Attribute Type code (MED)
				4,          // Length
				0, 0, 1, 0, // MED 256

				0,          // Attribute flags
				5,          // Attribute Type code (Local Pref)
				4,          // Length
				0, 0, 1, 0, // Local Pref 256

			},
			wantFail: false,
			expected: BGPUpdate{
				WithdrawnRoutesLen: 5,
				WithdrawnRoutes: []NLRI{
					{
						IP:     IPv4Addr{10, 0, 0, 0},
						Pfxlen: 8,
					},
					{
						IP:     IPv4Addr{192, 168, 0, 0},
						Pfxlen: 16,
					},
				},
				TotalPathAttrLen: 41,
				PathAttributes: []PathAttribute{
					{
						Optional:       true,
						Transitive:     true,
						Partial:        true,
						ExtendedLength: true,
						Length:         1,
						TypeCode:       1,
						Value:          Origin(2),
					},
					{
						Optional:       false,
						Transitive:     false,
						Partial:        false,
						ExtendedLength: false,
						Length:         12,
						TypeCode:       2,
						Value: ASPath{
							{
								Type:  2,
								Count: 2,
								ASNs: []ASN32{
									15169,
									3320,
								},
							},
							{
								Type:  1,
								Count: 2,
								ASNs: []ASN32{
									15169,
									3320,
								},
							},
						},
					},
					{
						Optional:       false,
						Transitive:     false,
						Partial:        false,
						ExtendedLength: false,
						Length:         4,
						TypeCode:       3,
						Value:          IPv4Addr{10, 11, 12, 13},
					},
					{
						Optional:       false,
						Transitive:     false,
						Partial:        false,
						ExtendedLength: false,
						Length:         4,
						TypeCode:       4,
						Value:          MED(256),
					},
					{
						Optional:       false,
						Transitive:     false,
						Partial:        false,
						ExtendedLength: false,
						Length:         4,
						TypeCode:       5,
						Value:          LocalPref(256),
					},
				},
			},
		},
		{
			// 2 withdraws with 6 path attributes (ORIGIN, ASPath, NH, MED, Local Pref, Atomi Aggregate), valid update
			testNum: 9,
			input: []byte{0, 5, 8, 10, 16, 192, 168,
				0, 44, // Total Path Attribute Length

				255,  // Attribute flags
				1,    // Attribute Type code (ORIGIN)
				0, 1, // Length
				2, // INCOMPLETE

				0,      // Attribute flags
				2,      // Attribute Type code (AS Path)
				12,     // Length
				2,      // Type = AS_SEQUENCE
				2,      // Path Segement Length
				59, 65, // AS15169
				12, 248, // AS3320
				1,      // Type = AS_SET
				2,      // Path Segement Length
				59, 65, // AS15169
				12, 248, // AS3320

				0,              // Attribute flags
				3,              // Attribute Type code (Next Hop)
				4,              // Length
				10, 11, 12, 13, // Next Hop

				0,          // Attribute flags
				4,          // Attribute Type code (MED)
				4,          // Length
				0, 0, 1, 0, // MED 256

				0,          // Attribute flags
				5,          // Attribute Type code (Local Pref)
				4,          // Length
				0, 0, 1, 0, // Local Pref 256

				0, // Attribute flags
				6, // Attribute Type code (Atomic Aggregate)
				0, // Length
			},
			wantFail: false,
			expected: BGPUpdate{
				WithdrawnRoutesLen: 5,
				WithdrawnRoutes: []NLRI{
					{
						IP:     IPv4Addr{10, 0, 0, 0},
						Pfxlen: 8,
					},
					{
						IP:     IPv4Addr{192, 168, 0, 0},
						Pfxlen: 16,
					},
				},
				TotalPathAttrLen: 44,
				PathAttributes: []PathAttribute{
					{
						Optional:       true,
						Transitive:     true,
						Partial:        true,
						ExtendedLength: true,
						Length:         1,
						TypeCode:       1,
						Value:          Origin(2),
					},
					{
						Optional:       false,
						Transitive:     false,
						Partial:        false,
						ExtendedLength: false,
						Length:         12,
						TypeCode:       2,
						Value: ASPath{
							{
								Type:  2,
								Count: 2,
								ASNs: []ASN32{
									15169,
									3320,
								},
							},
							{
								Type:  1,
								Count: 2,
								ASNs: []ASN32{
									15169,
									3320,
								},
							},
						},
					},
					{
						Optional:       false,
						Transitive:     false,
						Partial:        false,
						ExtendedLength: false,
						Length:         4,
						TypeCode:       3,
						Value:          IPv4Addr{10, 11, 12, 13},
					},
					{
						Optional:       false,
						Transitive:     false,
						Partial:        false,
						ExtendedLength: false,
						Length:         4,
						TypeCode:       4,
						Value:          MED(256),
					},
					{
						Optional:       false,
						Transitive:     false,
						Partial:        false,
						ExtendedLength: false,
						Length:         4,
						TypeCode:       5,
						Value:          LocalPref(256),
					},
					{
						Optional:       false,
						Transitive:     false,
						Partial:        false,
						ExtendedLength: false,
						Length:         0,
						TypeCode:       6,
					},
				},
			},
		},
		{
			// 2 withdraws with 7 path attributes (ORIGIN, ASPath, NH, MED, Local Pref, Atomic Aggregate), valid update
			testNum: 10,
			input: []byte{0, 5, 8, 10, 16, 192, 168,
				0, 53, // Total Path Attribute Length

				255,  // Attribute flags
				1,    // Attribute Type code (ORIGIN)
				0, 1, // Length
				2, // INCOMPLETE

				0,      // Attribute flags
				2,      // Attribute Type code (AS Path)
				12,     // Length
				2,      // Type = AS_SEQUENCE
				2,      // Path Segement Length
				59, 65, // AS15169
				12, 248, // AS3320
				1,      // Type = AS_SET
				2,      // Path Segement Length
				59, 65, // AS15169
				12, 248, // AS3320

				0,              // Attribute flags
				3,              // Attribute Type code (Next Hop)
				4,              // Length
				10, 11, 12, 13, // Next Hop

				0,          // Attribute flags
				4,          // Attribute Type code (MED)
				4,          // Length
				0, 0, 1, 0, // MED 256

				0,          // Attribute flags
				5,          // Attribute Type code (Local Pref)
				4,          // Length
				0, 0, 1, 0, // Local Pref 256

				0, // Attribute flags
				6, // Attribute Type code (Atomic Aggregate)
				0, // Length

				0,    // Attribute flags
				7,    // Attribute Type code (Atomic Aggregate)
				6,    // Length
				1, 2, // ASN
				10, 11, 12, 13, // Address

				8, 11, // 11.0.0.0/8
			},
			wantFail: false,
			expected: BGPUpdate{
				WithdrawnRoutesLen: 5,
				WithdrawnRoutes: []NLRI{
					{
						IP:     IPv4Addr{10, 0, 0, 0},
						Pfxlen: 8,
					},
					{
						IP:     IPv4Addr{192, 168, 0, 0},
						Pfxlen: 16,
					},
				},
				TotalPathAttrLen: 53,
				PathAttributes: []PathAttribute{
					{
						Optional:       true,
						Transitive:     true,
						Partial:        true,
						ExtendedLength: true,
						Length:         1,
						TypeCode:       1,
						Value:          Origin(2),
					},
					{
						Optional:       false,
						Transitive:     false,
						Partial:        false,
						ExtendedLength: false,
						Length:         12,
						TypeCode:       2,
						Value: ASPath{
							{
								Type:  2,
								Count: 2,
								ASNs: []ASN32{
									15169,
									3320,
								},
							},
							{
								Type:  1,
								Count: 2,
								ASNs: []ASN32{
									15169,
									3320,
								},
							},
						},
					},
					{
						Optional:       false,
						Transitive:     false,
						Partial:        false,
						ExtendedLength: false,
						Length:         4,
						TypeCode:       3,
						Value:          IPv4Addr{10, 11, 12, 13},
					},
					{
						Optional:       false,
						Transitive:     false,
						Partial:        false,
						ExtendedLength: false,
						Length:         4,
						TypeCode:       4,
						Value:          MED(256),
					},
					{
						Optional:       false,
						Transitive:     false,
						Partial:        false,
						ExtendedLength: false,
						Length:         4,
						TypeCode:       5,
						Value:          LocalPref(256),
					},
					{
						Optional:       false,
						Transitive:     false,
						Partial:        false,
						ExtendedLength: false,
						Length:         0,
						TypeCode:       6,
					},
					{
						Optional:       false,
						Transitive:     false,
						Partial:        false,
						ExtendedLength: false,
						Length:         6,
						TypeCode:       7,
						Value: Aggretator{
							ASN:  ASN16(258),
							Addr: IPv4Addr{10, 11, 12, 13},
						},
					},
				},
				NLRI: []NLRI{
					{
						Pfxlen: 8,
						IP:     IPv4Addr{11, 0, 0, 0},
					},
				},
			},
		},
	}

	for _, test := range tests {
		buf := bytes.NewBuffer(test.input)
		msg, err := decodeUpdateMsg(buf, MsgLength(len(test.input)))

		if err != nil && !test.wantFail {
			t.Errorf("Unexpected error in test %d: %v", test.testNum, err)
			continue
		}

		if err == nil && test.wantFail {
			t.Errorf("Expected error did not happen in test %d", test.testNum)
			continue
		}

		if err != nil && test.wantFail {
			continue
		}

		assert.Equal(t, test.expected, msg)
	}
}

func TestDecodeOpenMsg(t *testing.T) {
	tests := []test{
		{
			// Valid message
			testNum:  1,
			input:    []byte{4, 1, 1, 0, 15, 0, 0, 10, 11, 0},
			wantFail: false,
			expected: BGPOpen{
				Version:       4,
				AS:            257,
				HoldTime:      15,
				BGPIdentifier: 2571,
				OptParmLen:    0,
			},
		},
		{
			// Invalid Version
			testNum:  2,
			input:    []byte{3, 1, 1, 0, 15, 10, 10, 10, 11, 0},
			wantFail: true,
		},
	}

	genericTest(_decodeOpenMsg, tests, t)
}

func TestDecodeHeader(t *testing.T) {
	tests := []test{
		{
			// Valid header
			testNum:  1,
			input:    []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 19, KeepaliveMsg},
			wantFail: false,
			expected: BGPHeader{
				Length: 19,
				Type:   KeepaliveMsg,
			},
		},
		{
			// Invalid length too short
			testNum:  2,
			input:    []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 18, KeepaliveMsg},
			wantFail: true,
			expected: BGPHeader{
				Length: 18,
				Type:   KeepaliveMsg,
			},
		},
		{
			// Invalid length too long
			testNum:  3,
			input:    []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 16, 1, KeepaliveMsg},
			wantFail: true,
			expected: BGPHeader{
				Length: 18,
				Type:   KeepaliveMsg,
			},
		},
		{
			// Invalid message type 5
			testNum:  4,
			input:    []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 19, 5},
			wantFail: true,
			expected: BGPHeader{
				Length: 19,
				Type:   KeepaliveMsg,
			},
		},
		{
			// Invalid message type 0
			testNum:  5,
			input:    []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 19, 0},
			wantFail: true,
			expected: BGPHeader{
				Length: 19,
				Type:   KeepaliveMsg,
			},
		},
		{
			// Invalid marker
			testNum:  6,
			input:    []byte{1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 19, KeepaliveMsg},
			wantFail: true,
			expected: BGPHeader{
				Length: 19,
				Type:   KeepaliveMsg,
			},
		},
	}

	genericTest(_decodeHeader, tests, t)
}

func genericTest(f decodeFunc, tests []test, t *testing.T) {
	for _, test := range tests {
		buf := bytes.NewBuffer(test.input)
		msg, err := f(buf)

		if err != nil && !test.wantFail {
			t.Errorf("Unexpected error in test %d: %v", test.testNum, err)
			continue
		}

		if err == nil && test.wantFail {
			t.Errorf("Expected error did not happen in test %d", test.testNum)
			continue
		}

		if err != nil && test.wantFail {
			continue
		}

		if msg == nil {
			t.Errorf("Unexpected nil result in test %d. Expected: %v", test.testNum, test.expected)
			continue
		}

		assert.Equal(t, test.expected, msg)
	}
}
