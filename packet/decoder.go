package packet

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"net"
)

type Decoder struct {
	objManager *objManager
}

func NewDecoder() *Decoder {
	return &Decoder{
		objManager: newObjManager(),
	}
}

// Decode decodes a BGP message
func (d *Decoder) Decode(buf *bytes.Buffer) (*BGPMessage, error) {
	hdr, err := decodeHeader(buf)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode header: %v", err)
	}

	body, err := d.decodeMsgBody(buf, hdr.Type, hdr.Length)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode message: %v", err)
	}

	return &BGPMessage{
		Header: &hdr,
		Body:   body,
	}, nil
}

func (d *Decoder) decodeMsgBody(buf *bytes.Buffer, msgType uint8, l uint16) (interface{}, error) {
	switch msgType {
	case OpenMsg:
		return decodeOpenMsg(buf)
	case UpdateMsg:
		return d.decodeUpdateMsg(buf, l)
	case KeepaliveMsg:
		return nil, nil // Nothing to decode in Keepalive message
	case NotificationMsg:
		return decodeNotificationMsg(buf)
	}
	return nil, fmt.Errorf("Unknown message type: %d", msgType)
}

func (d *Decoder) decodeUpdateMsg(buf *bytes.Buffer, l uint16) (*BGPUpdate, error) {
	msg := d.objManager.getBGPUpdate()

	err := decode(buf, []interface{}{&msg.WithdrawnRoutesLen})
	if err != nil {
		return msg, err
	}

	msg.WithdrawnRoutes, err = d.decodeNLRI(buf, uint16(msg.WithdrawnRoutesLen))
	if err != nil {
		return msg, nil
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
		msg.NLRI, err = d.decodeNLRI(buf, nlriLen)
		if err != nil {
			return msg, err
		}
	}

	return msg, nil
}

func (d *Decoder) decodeNLRI(buf *bytes.Buffer, l uint16) (*NLRI, error) {
	var ret *NLRI
	var eol *NLRI
	var nlri *NLRI
	var toCopy uint8
	var j uint8
	var err error
	p := uint16(0)
	for p < l {
		nlri = d.objManager.getNLRI()
		if ret == nil {
			ret = nlri
			eol = nlri
		} else {
			eol.Next = nlri
			eol = nlri
		}

		err = decode(buf, []interface{}{&nlri.Pfxlen})
		if err != nil {
			return nil, err
		}
		p++

		toCopy = uint8(math.Ceil(float64(nlri.Pfxlen) / float64(OctetLen)))
		var addr [4]byte
		for j = 0; j < net.IPv4len%OctetLen; j++ {
			if j < toCopy {
				err = decode(buf, []interface{}{&addr[j]})
				if err != nil {
					return nil, err
				}
			} else {
				addr[j] = 0
			}
		}
		nlri.IP = addr
		p += uint16(toCopy)

	}

	return ret, nil
}

func decodePathAttrs(buf *bytes.Buffer, tpal uint16) ([]PathAttribute, error) {
	attrs := make([]PathAttribute, 0)

	p := uint16(0)
	for p < tpal {
		pa := PathAttribute{}

		err := decodePathAttrFlags(buf, &pa)
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
		attrs = append(attrs, pa)
	}

	return attrs, nil
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

func decodeNotificationMsg(buf *bytes.Buffer) (BGPNotification, error) {
	msg, err := _decodeNotificationMsg(buf)
	return msg.(BGPNotification), err
}

func _decodeNotificationMsg(buf *bytes.Buffer) (interface{}, error) {
	msg := BGPNotification{}

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
			return invalidErrCode(&msg)
		}
	case OpenMessageError:
		if msg.ErrorSubcode > UnacceptableHoldTime || msg.ErrorSubcode == 0 || msg.ErrorSubcode == DeprecatedOpenMsgError5 {
			return invalidErrCode(&msg)
		}
	case UpdateMessageError:
		if msg.ErrorSubcode > MalformedASPath || msg.ErrorSubcode == 0 || msg.ErrorSubcode == DeprecatedUpdateMsgError7 {
			return invalidErrCode(&msg)
		}
	case HoldTimeExpired:
		if msg.ErrorSubcode != 0 {
			return invalidErrCode(&msg)
		}
	case FiniteStateMachineError:
		if msg.ErrorSubcode != 0 {
			return invalidErrCode(&msg)
		}
	case Cease:
		if msg.ErrorSubcode != 0 {
			return invalidErrCode(&msg)
		}
	default:
		return invalidErrCode(&msg)
	}

	return msg, nil
}

func invalidErrCode(n *BGPNotification) (BGPNotification, error) {
	return *n, fmt.Errorf("Invalid error sub code: %d/%d", n.ErrorCode, n.ErrorSubcode)
}

func decodeOpenMsg(buf *bytes.Buffer) (BGPOpen, error) {
	msg, err := _decodeOpenMsg(buf)
	return msg.(BGPOpen), err
}

func _decodeOpenMsg(buf *bytes.Buffer) (interface{}, error) {
	msg := BGPOpen{}

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

	if msg.Version != 4 {
		return msg, fmt.Errorf("Invalid version: %d", msg.Version)
	}

	return msg, nil
}

func decodeHeader(buf *bytes.Buffer) (BGPHeader, error) {
	msg, err := _decodeHeader(buf)
	return msg.(BGPHeader), err
}

func _decodeHeader(buf *bytes.Buffer) (interface{}, error) {
	hdr := BGPHeader{}

	marker := make([]byte, MarkerLen)
	n, err := buf.Read(marker)
	if err != nil {
		return hdr, fmt.Errorf("Failed to read from buffer: %v", err)
	}

	if n != MarkerLen {
		return hdr, fmt.Errorf("Unable to read marker")
	}

	for i := range marker {
		if marker[i] != 1 {
			return hdr, fmt.Errorf("Invalid marker: %v", marker)
		}
	}

	fields := []interface{}{
		&hdr.Length,
		&hdr.Type,
	}

	err = decode(buf, fields)
	if err != nil {
		return hdr, err
	}

	if hdr.Length < MinLen || hdr.Length > MaxLen {
		return hdr, fmt.Errorf("Invalid length in BGP header: %v", hdr.Length)
	}

	if hdr.Type > KeepaliveMsg || hdr.Type == 0 {
		return hdr, fmt.Errorf("Invalid message type: %d", hdr.Type)
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
