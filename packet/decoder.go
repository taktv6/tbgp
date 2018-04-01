package packet

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"net"

	"github.com/taktv6/tflow2/convert"
)

// Decode decodes a BGP message
func Decode(buf *bytes.Buffer) (*BGPMessage, error) {
	hdr, err := decodeHeader(buf)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode header: %v", err)
	}

	body, err := decodeMsgBody(buf, hdr.Type, hdr.Length-MinLen)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode message: %v", err)
	}

	return &BGPMessage{
		Header: hdr,
		Body:   body,
	}, nil
}

func decodeMsgBody(buf *bytes.Buffer, msgType uint8, l uint16) (interface{}, error) {
	switch msgType {
	case OpenMsg:
		return decodeOpenMsg(buf)
	case UpdateMsg:
		return decodeUpdateMsg(buf, l)
	case KeepaliveMsg:
		return nil, nil // Nothing to decode in Keepalive message
	case NotificationMsg:
		return decodeNotificationMsg(buf)
	}
	return nil, fmt.Errorf("Unknown message type: %d", msgType)
}

func decodeUpdateMsg(buf *bytes.Buffer, l uint16) (*BGPUpdate, error) {
	msg := &BGPUpdate{}

	err := decode(buf, []interface{}{&msg.WithdrawnRoutesLen})
	if err != nil {
		return msg, err
	}

	msg.WithdrawnRoutes, err = decodeNLRIs(buf, uint16(msg.WithdrawnRoutesLen))
	if err != nil {
		return msg, err
	}

	err = decode(buf, []interface{}{&msg.TotalPathAttrLen})
	if err != nil {
		return msg, err
	}

	msg.PathAttributes, err = decodePathAttrs(buf, msg.TotalPathAttrLen)
	if err != nil {
		return msg, err
	}

	nlriLen := uint16(l) - 4 - uint16(msg.TotalPathAttrLen) - uint16(msg.WithdrawnRoutesLen)
	if nlriLen > 0 {
		msg.NLRI, err = decodeNLRIs(buf, nlriLen)
		if err != nil {
			return msg, err
		}
	}

	return msg, nil
}

func decodeNLRIs(buf *bytes.Buffer, length uint16) (*NLRI, error) {
	var ret *NLRI
	var eol *NLRI
	var nlri *NLRI
	var err error
	var consumed uint8
	p := uint16(0)

	for p < length {
		nlri, consumed, err = decodeNLRI(buf)
		if err != nil {
			return nil, fmt.Errorf("Unable to decode NLRI: %v", err)
		}
		p += uint16(consumed)

		if ret == nil {
			ret = nlri
			eol = nlri
			continue
		}

		eol.Next = nlri
		eol = nlri
	}

	return ret, nil
}

func decodeNLRI(buf *bytes.Buffer) (*NLRI, uint8, error) {
	var addr [4]byte
	nlri := &NLRI{}

	err := decode(buf, []interface{}{&nlri.Pfxlen})
	if err != nil {
		return nil, 0, err
	}

	toCopy := uint8(math.Ceil(float64(nlri.Pfxlen) / float64(OctetLen)))
	for i := uint8(0); i < net.IPv4len%OctetLen; i++ {
		if i < toCopy {
			err := decode(buf, []interface{}{&addr[i]})
			if err != nil {
				return nil, 0, err
			}
		} else {
			addr[i] = 0
		}
	}
	nlri.IP = addr
	return nlri, toCopy + 1, nil
}

func decodePathAttrs(buf *bytes.Buffer, tpal uint16) (*PathAttribute, error) {
	var ret *PathAttribute
	var eol *PathAttribute
	var pa *PathAttribute

	p := uint16(0)
	for p < tpal {
		pa = &PathAttribute{}
		if ret == nil {
			ret = pa
			eol = pa
		} else {
			eol.Next = pa
			eol = pa
		}

		err := decodePathAttrFlags(buf, pa)
		if err != nil {
			return nil, fmt.Errorf("Unable to get path attribute flags: %v", err)
		}
		p++

		err = decode(buf, []interface{}{&pa.TypeCode})
		if err != nil {
			return nil, err
		}
		p++

		n, err := pa.setLength(buf)
		if err != nil {
			return nil, err
		}
		p += uint16(n)

		switch pa.TypeCode {
		case OriginAttr:
			pa.decodeOrigin(buf)
		case ASPathAttr:
			if err := pa.decodeASPath(buf); err != nil {
				return nil, fmt.Errorf("Failed to decode AS Path: %v", err)
			}
		case NextHopAttr:
			if err := pa.decodeNextHop(buf); err != nil {
				return nil, fmt.Errorf("Failed to decode Next-Hop: %v", err)
			}
		case MEDAttr:
			if err := pa.decodeMED(buf); err != nil {
				return nil, fmt.Errorf("Failed to decode MED: %v", err)
			}
		case LocalPrefAttr:
			if err := pa.decodeLocalPref(buf); err != nil {
				return nil, fmt.Errorf("Failed to decode local pref: %v", err)
			}
		case AtomicAggrAttr:
			// Nothing to do for 0 octet long attribute
		case AggregatorAttr:
			if err := pa.decodeAggregator(buf); err != nil {
				return nil, fmt.Errorf("Failed to decode Aggregator: %v", err)
			}
		default:
			return nil, fmt.Errorf("Invalid Attribute Type Code: %v", pa.TypeCode)
		}

		p += uint16(pa.Length)

	}

	return ret, nil
}

func (pa *PathAttribute) decodeAggregator(buf *bytes.Buffer) error {
	aggr := Aggretator{}

	p := uint16(0)
	err := decode(buf, []interface{}{&aggr.ASN})
	if err != nil {
		return err
	}
	p += 2

	n, err := buf.Read(aggr.Addr[:])
	if err != nil {
		return err
	}
	if n != 4 {
		return fmt.Errorf("Unable to read aggregator IP: buf.Read read %d bytes", n)
	}
	p += 4

	pa.Value = aggr
	return dumpNBytes(buf, pa.Length-p)
}

func (pa *PathAttribute) decodeLocalPref(buf *bytes.Buffer) error {
	lpref, err := pa.decodeUint32(buf)
	if err != nil {
		return fmt.Errorf("Unable to recode local pref: %v", err)
	}

	pa.Value = uint32(lpref)
	return nil
}

func (pa *PathAttribute) decodeMED(buf *bytes.Buffer) error {
	med, err := pa.decodeUint32(buf)
	if err != nil {
		return fmt.Errorf("Unable to recode local pref: %v", err)
	}

	pa.Value = uint32(med)
	return nil
}

func (pa *PathAttribute) decodeUint32(buf *bytes.Buffer) (uint32, error) {
	var v uint32

	p := uint16(0)
	err := decode(buf, []interface{}{&v})
	if err != nil {
		return 0, err
	}

	p += 4
	err = dumpNBytes(buf, pa.Length-p)
	if err != nil {
		return 0, fmt.Errorf("dumpNBytes failed: %v", err)
	}

	return v, nil
}

func (pa *PathAttribute) decodeNextHop(buf *bytes.Buffer) error {
	addr := [4]byte{}

	p := uint16(0)
	n, err := buf.Read(addr[:])
	if err != nil {
		return err
	}
	if n != 4 {
		return fmt.Errorf("Unable to read next hop: buf.Read read %d bytes", n)
	}

	pa.Value = addr
	p += 4

	return dumpNBytes(buf, pa.Length-p)
}

func (pa *PathAttribute) decodeASPath(buf *bytes.Buffer) error {
	pa.Value = make(ASPath, 0)

	p := uint16(0)
	for p < pa.Length {
		segment := ASPathSegment{
			ASNs: make([]uint32, 0),
		}

		err := decode(buf, []interface{}{&segment.Type, &segment.Count})
		if err != nil {
			return err
		}
		p += 2

		if segment.Type != ASSet && segment.Type != ASSequence {
			return fmt.Errorf("Invalid AS Path segment type: %d", segment.Type)
		}

		if segment.Count == 0 {
			return fmt.Errorf("Invalid AS Path segment length: %d", segment.Count)
		}

		for i := uint8(0); i < segment.Count; i++ {
			asn := uint16(0)

			err := decode(buf, []interface{}{&asn})
			if err != nil {
				return err
			}
			p += 2

			segment.ASNs = append(segment.ASNs, uint32(asn))
		}
		pa.Value = append(pa.Value.(ASPath), segment)
	}

	return nil
}

func (pa *PathAttribute) decodeOrigin(buf *bytes.Buffer) error {
	origin := uint8(0)

	p := uint16(0)
	err := decode(buf, []interface{}{&origin})
	if err != nil {
		return err
	}

	pa.Value = origin
	p++

	return dumpNBytes(buf, pa.Length-p)
}

// dumpNBytes is used to dump n bytes of buf. This is useful in case an path attributes
// length doesn't match a fixed length's attributes length (e.g. ORIGIN is always an octet)
func dumpNBytes(buf *bytes.Buffer, n uint16) error {
	if n == 0 {
		return nil
	}
	dump := make([]byte, n)
	err := decode(buf, []interface{}{&dump})
	if err != nil {
		return err
	}
	return nil
}

func (pa *PathAttribute) setLength(buf *bytes.Buffer) (int, error) {
	bytesRead := 0
	if pa.ExtendedLength {
		err := decode(buf, []interface{}{&pa.Length})
		if err != nil {
			return 0, err
		}
		bytesRead = 2
	} else {
		x := uint8(0)
		err := decode(buf, []interface{}{&x})
		if err != nil {
			return 0, err
		}
		pa.Length = uint16(x)
		bytesRead = 1
	}
	return bytesRead, nil
}

func decodePathAttrFlags(buf *bytes.Buffer, pa *PathAttribute) error {
	flags := uint8(0)
	err := decode(buf, []interface{}{&flags})
	if err != nil {
		return err
	}

	pa.Optional = isOptional(flags)
	pa.Transitive = isTransitive(flags)
	pa.Partial = isPartial(flags)
	pa.ExtendedLength = isExtendedLength(flags)

	return nil
}

func isOptional(x uint8) bool {
	if x&128 == 128 {
		return true
	}
	return false
}

func isTransitive(x uint8) bool {
	if x&64 == 64 {
		return true
	}
	return false
}

func isPartial(x uint8) bool {
	if x&32 == 32 {
		return true
	}
	return false
}

func isExtendedLength(x uint8) bool {
	if x&16 == 16 {
		return true
	}
	return false
}

func decodeNotificationMsg(buf *bytes.Buffer) (*BGPNotification, error) {
	msg, err := _decodeNotificationMsg(buf)
	return msg.(*BGPNotification), err
}

func _decodeNotificationMsg(buf *bytes.Buffer) (interface{}, error) {
	msg := &BGPNotification{}

	fields := []interface{}{
		&msg.ErrorCode,
		&msg.ErrorSubcode,
	}

	err := decode(buf, fields)
	if err != nil {
		return msg, err
	}

	if msg.ErrorCode > Cease {
		return msg, fmt.Errorf("Invalid error code: %d", msg.ErrorSubcode)
	}

	switch msg.ErrorCode {
	case MessageHeaderError:
		if msg.ErrorSubcode > BadMessageType || msg.ErrorSubcode == 0 {
			return invalidErrCode(msg)
		}
	case OpenMessageError:
		if msg.ErrorSubcode > UnacceptableHoldTime || msg.ErrorSubcode == 0 || msg.ErrorSubcode == DeprecatedOpenMsgError5 {
			return invalidErrCode(msg)
		}
	case UpdateMessageError:
		if msg.ErrorSubcode > MalformedASPath || msg.ErrorSubcode == 0 || msg.ErrorSubcode == DeprecatedUpdateMsgError7 {
			return invalidErrCode(msg)
		}
	case HoldTimeExpired:
		if msg.ErrorSubcode != 0 {
			return invalidErrCode(msg)
		}
	case FiniteStateMachineError:
		if msg.ErrorSubcode != 0 {
			return invalidErrCode(msg)
		}
	case Cease:
		if msg.ErrorSubcode != 0 {
			return invalidErrCode(msg)
		}
	default:
		return invalidErrCode(msg)
	}

	return msg, nil
}

func invalidErrCode(n *BGPNotification) (*BGPNotification, error) {
	return n, fmt.Errorf("Invalid error sub code: %d/%d", n.ErrorCode, n.ErrorSubcode)
}

func decodeOpenMsg(buf *bytes.Buffer) (*BGPOpen, error) {
	msg, err := _decodeOpenMsg(buf)
	return msg.(*BGPOpen), err
}

func _decodeOpenMsg(buf *bytes.Buffer) (interface{}, error) {
	msg := &BGPOpen{}

	fields := []interface{}{
		&msg.Version,
		&msg.AS,
		&msg.HoldTime,
		&msg.BGPIdentifier,
		&msg.OptParmLen,
	}

	err := decode(buf, fields)
	if err != nil {
		return msg, err
	}

	err = validateOpen(msg)
	if err != nil {
		return nil, err
	}

	return msg, nil
}

func validateOpen(msg *BGPOpen) error {
	if msg.Version != BGP4Version {
		return BGPError{
			ErrorCode:    OpenMessageError,
			ErrorSubCode: UnsupportedVersionNumber,
			ErrorStr:     fmt.Sprintf("Unsupported version number"),
		}
	}
	if !isValidIdentifier(msg.BGPIdentifier) {
		return BGPError{
			ErrorCode:    OpenMessageError,
			ErrorSubCode: BadBGPIdentifier,
			ErrorStr:     fmt.Sprintf("Invalid BGP identifier"),
		}
	}

	return nil
}

func isValidIdentifier(id uint32) bool {
	addr := net.IP(convert.Uint32Byte(id))
	if addr.IsLoopback() {
		return false
	}

	if addr.IsMulticast() {
		return false
	}

	if addr[0] == 0 {
		return false
	}

	if addr[0] == 255 && addr[1] == 255 && addr[2] == 255 && addr[3] == 255 {
		return false
	}

	return true
}

func decodeHeader(buf *bytes.Buffer) (*BGPHeader, error) {
	msg, err := _decodeHeader(buf)
	if err != nil {
		return nil, err
	}
	return msg.(*BGPHeader), err
}

func _decodeHeader(buf *bytes.Buffer) (interface{}, error) {
	hdr := &BGPHeader{}

	marker := make([]byte, MarkerLen)
	n, err := buf.Read(marker)
	if err != nil {
		return hdr, BGPError{
			ErrorCode:    Cease,
			ErrorSubCode: 0,
			ErrorStr:     fmt.Sprintf("Failed to read from buffer: %v", err.Error()),
		}
	}

	if n != MarkerLen {
		return hdr, BGPError{
			ErrorCode:    Cease,
			ErrorSubCode: 0,
			ErrorStr:     fmt.Sprintf("Unable to read marker"),
		}
	}

	for i := range marker {
		if marker[i] != 255 {
			return nil, BGPError{
				ErrorCode:    MessageHeaderError,
				ErrorSubCode: ConnectionNotSync,
				ErrorStr:     fmt.Sprintf("Invalid marker: %v", marker),
			}
		}
	}

	fields := []interface{}{
		&hdr.Length,
		&hdr.Type,
	}

	err = decode(buf, fields)
	if err != nil {
		return hdr, BGPError{
			ErrorCode:    Cease,
			ErrorSubCode: 0,
			ErrorStr:     fmt.Sprintf("%v", err.Error()),
		}
	}

	if hdr.Length < MinLen || hdr.Length > MaxLen {
		return hdr, BGPError{
			ErrorCode:    MessageHeaderError,
			ErrorSubCode: BadMessageLength,
			ErrorStr:     fmt.Sprintf("Invalid length in BGP header: %v", hdr.Length),
		}
	}

	if hdr.Type > KeepaliveMsg || hdr.Type == 0 {
		return hdr, BGPError{
			ErrorCode:    MessageHeaderError,
			ErrorSubCode: BadMessageType,
			ErrorStr:     fmt.Sprintf("Invalid message type: %d", hdr.Type),
		}
	}

	return hdr, nil
}

func decode(buf *bytes.Buffer, fields []interface{}) error {
	var err error
	for _, field := range fields {
		err = binary.Read(buf, binary.BigEndian, field)
		if err != nil {
			return fmt.Errorf("Unable to read from buffer: %v", err)
		}
	}
	return nil
}

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
