package packet

import (
	"bytes"

	"github.com/taktv6/tflow2/convert"
)

func EncodeKeepaliveMsg() ([]byte, error) {
	keepaliveLen := uint16(19)
	buf := bytes.NewBuffer(make([]byte, 0, keepaliveLen))
	err := encodeHeader(buf, keepaliveLen, KeepaliveMsg)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func EncodeNotificationMsg(msg *BGPNotification) ([]byte, error) {
	notificationLen := uint16(21)
	buf := bytes.NewBuffer(make([]byte, 0, notificationLen))
	err := encodeHeader(buf, notificationLen, NotificationMsg)
	if err != nil {
		return nil, err
	}

	err = buf.WriteByte(msg.ErrorCode)
	if err != nil {
		return nil, err
	}

	err = buf.WriteByte(msg.ErrorSubcode)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func EncodeOpenMsg(msg *BGPOpen) ([]byte, error) {
	openLen := uint16(29)
	buf := bytes.NewBuffer(make([]byte, 0, openLen))
	err := encodeHeader(buf, openLen, OpenMsg)
	if err != nil {
		return nil, err
	}

	err = buf.WriteByte(msg.Version)
	if err != nil {
		return nil, err
	}

	_, err = buf.Write(convert.Uint16Byte(msg.AS))
	if err != nil {
		return nil, err
	}

	_, err = buf.Write(convert.Uint16Byte(msg.HoldTime))
	if err != nil {
		return nil, err
	}

	_, err = buf.Write(convert.Uint32Byte(msg.BGPIdentifier))
	if err != nil {
		return nil, err
	}

	err = buf.WriteByte(uint8(0))
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func encodeHeader(buf *bytes.Buffer, length uint16, typ uint8) error {
	for i := 0; i < 16; i++ {
		if err := buf.WriteByte(0xff); err != nil {
			return err
		}
	}

	if _, err := buf.Write(convert.Uint16Byte(length)); err != nil {
		return err
	}

	if err := buf.WriteByte(typ); err != nil {
		return err
	}

	return nil
}
