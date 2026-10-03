package mapping

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
)

type NativeCapture struct{}

func readPCAP(r io.Reader, in Input, deliver func(Injection)) error {
	return readPCAPReady(r, in, deliver, nil)
}

func readPCAPReady(r io.Reader, in Input, deliver func(Injection), ready func()) error {
	r = bufio.NewReader(r)
	header := make([]byte, 24)
	if _, err := io.ReadFull(r, header); err != nil {
		return err
	}
	var order binary.ByteOrder
	switch string(header[:4]) {
	case "\xd4\xc3\xb2\xa1", "\x4d\x3c\xb2\xa1":
		order = binary.LittleEndian
	case "\xa1\xb2\xc3\xd4", "\xa1\xb2\x3c\x4d":
		order = binary.BigEndian
	default:
		return errors.New("unsupported capture format")
	}
	link := order.Uint32(header[20:24])
	if link != 1 && link != 0 && link != 12 {
		return fmt.Errorf("unsupported capture link type %d", link)
	}
	if order.Uint32(header[16:20]) > 65535 {
		return errors.New("unexpected capture snapshot limit")
	}
	if ready != nil {
		ready()
	}
	record := make([]byte, 16)
	for {
		if _, err := io.ReadFull(r, record); err != nil {
			return err
		}
		n := order.Uint32(record[8:12])
		if n > 65535 {
			return errors.New("oversized capture record")
		}
		packet := make([]byte, n)
		if _, err := io.ReadFull(r, packet); err != nil {
			return err
		}
		if injection, ok := capturedDiscovery(packet, link, in); ok {
			deliver(injection)
		}
	}
}

func capturedDiscovery(frame []byte, link uint32, in Input) (Injection, bool) {
	var empty Injection
	offset := 0
	if link == 1 {
		if len(frame) < 14 {
			return empty, false
		}
		offset = 14
		ether := binary.BigEndian.Uint16(frame[12:14])
		if ether == 0x8100 || ether == 0x88a8 {
			if len(frame) < 18 {
				return empty, false
			}
			offset, ether = 18, binary.BigEndian.Uint16(frame[16:18])
		}
		if ether != 0x0800 {
			return empty, false
		}
	} else if link == 0 {
		offset = 4
	}
	if len(frame) < offset+20 {
		return empty, false
	}
	ip := frame[offset:]
	hl := int(ip[0]&15) * 4
	length := int(binary.BigEndian.Uint16(ip[2:4]))
	if ip[0]>>4 != 4 || hl < 20 || length < hl+8 || len(ip) < length || ip[9] != 17 || binary.BigEndian.Uint16(ip[6:8])&0x3fff != 0 {
		return empty, false
	}
	udp := ip[hl:length]
	ul := int(binary.BigEndian.Uint16(udp[4:6]))
	if ul < 8 || ul != len(udp) {
		return empty, false
	}
	source := netip.AddrPortFrom(netip.AddrFrom4([4]byte(ip[12:16])), binary.BigEndian.Uint16(udp[:2]))
	dest := netip.AddrPortFrom(netip.AddrFrom4([4]byte(ip[16:20])), binary.BigEndian.Uint16(udp[2:4]))
	packet := udp[8:]
	req := Injection{Packet: append([]byte(nil), packet...)}
	var public [32]byte
	if source == in.Native {
		req.Direction, req.Peer, public = "out", dest, in.SelfDisco
	} else if dest == in.Native {
		req.Direction, req.Peer, public = "in", source, in.PeerDisco
	} else {
		return empty, false
	}
	allowed := false
	for _, ap := range in.Peers {
		allowed = allowed || req.Peer == ap
	}
	if req.Direction == "in" {
		a := req.Peer.Addr()
		allowed = allowed || req.Peer.Port() != 0 && a.IsGlobalUnicast() && !a.IsLoopback() && a != in.Native.Addr()
	}
	return req, allowed && discoFrom(packet, public)
}
