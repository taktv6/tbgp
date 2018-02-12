package packet

type MsgType uint8
type MsgLength uint16

type Version uint8
type ASN16 uint16
type ASN32 uint32
type HoldTime uint16
type BGPIdentifier uint32
type OptParmLen uint8

type ErrorCore uint8
type ErrorSubCode uint8

type WithdrawnRoutesLen uint16
type TotalPathAttrLen uint16
type AttrTypeCode uint8

const (
	OctetLen = 8

	MarkerLen = 16
	HeaderLen = 19
	MinLen    = 19
	MaxLen    = 4096

	OpenMsg         = 1
	UpdateMsg       = 2
	NotificationMsg = 3
	KeepaliveMsg    = 4

	MessageHeaderError      = 1
	OpenMessageError        = 2
	UpdateMessageError      = 3
	HoldTimeExpired         = 4
	FiniteStateMachineError = 5
	Cease                   = 6

	// Msg Header Errors
	ConnectionNotSync = 1
	BadMessageLength  = 2
	BadMessageType    = 3

	// Open Msg Errors
	UnsupportedVersionNumber     = 1
	BadPeerAS                    = 2
	BadBGPIdentifier             = 3
	UnsupportedOptionalParameter = 4
	DeprecatedOpenMsgError5      = 5
	UnacceptableHoldTime         = 6

	// Update Msg Errors
	MalformedAttributeList    = 1
	UnrecognizedWellKnownAttr = 2
	MissingWellKnonAttr       = 3
	AttrFlagsError            = 4
	AttrLengthError           = 5
	InvalidOriginAttr         = 6
	DeprecatedUpdateMsgError7 = 7
	InvalidNextHopAttr        = 8
	OptionalAttError          = 9
	InvalidNetworkField       = 10
	MalformedASPath           = 11

	// Attribute Type Codes
	OriginAttr     = 1
	ASPathAttr     = 2
	NextHopAttr    = 3
	MEDAttr        = 4
	LocalPrefAttr  = 5
	AtomicAggrAttr = 6
	AggregatorAttr = 7

	// ORIGIN values
	IGP        = 0
	EGP        = 1
	INCOMPLETE = 2

	// ASPath Segment Types
	ASSet      = 1
	ASSequence = 2
)

type BGPMessage struct {
	Header *BGPHeader
	Body   interface{}
}

type BGPHeader struct {
	Length MsgLength
	Type   MsgType
}

type BGPOpen struct {
	Version       Version
	AS            ASN16
	HoldTime      HoldTime
	BGPIdentifier BGPIdentifier
	OptParmLen    OptParmLen
}

type BGPNotification struct {
	ErrorCode    ErrorCore
	ErrorSubcode ErrorSubCode
}

type BGPUpdate struct {
	WithdrawnRoutesLen WithdrawnRoutesLen
	WithdrawnRoutes    []NLRI
	TotalPathAttrLen   TotalPathAttrLen
	PathAttributes     []PathAttribute
	NLRI               []NLRI
}

type PathAttribute struct {
	Length         uint16
	Optional       bool
	Transitive     bool
	Partial        bool
	ExtendedLength bool
	TypeCode       AttrTypeCode
	Value          interface{}
}

type IPv4Addr [4]byte
type IPv6Addr [16]byte
type Pfxlen uint8

type NLRI struct {
	IP     interface{}
	Pfxlen Pfxlen
}

type Origin uint8
type MED uint32
type LocalPref uint32
type AtomicAggregate bool

type ASPath []ASPathSegment
type ASPathSegment struct {
	Type  uint8
	Count uint8
	ASNs  []ASN32
}

type Aggretator struct {
	Addr IPv4Addr
	ASN  ASN16
}
