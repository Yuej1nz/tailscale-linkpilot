package mapping

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

func captureFixture(in Input, source, dest netip.AddrPort, payload []byte) []byte {
	frame := make([]byte, 14+20+8+len(payload))
	binary.BigEndian.PutUint16(frame[12:14], 0x800)
	ip := frame[14:]
	ip[0], ip[9] = 0x45, 17
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	a, b := source.Addr().As4(), dest.Addr().As4()
	copy(ip[12:16], a[:])
	copy(ip[16:20], b[:])
	udp := ip[20:]
	binary.BigEndian.PutUint16(udp[0:2], source.Port())
	binary.BigEndian.PutUint16(udp[2:4], dest.Port())
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)
	return frame
}

func TestCaptureCopiesOnlyCompleteSelectedDiscoveryCiphertext(t *testing.T) {
	in := Input{Native: netip.MustParseAddrPort("192.0.2.1:41641"), SelfDisco: [32]byte{1}, PeerDisco: [32]byte{2}, Peers: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.2:41641")}}
	good := captureFixture(in, in.Native, in.Peers[0], discoFixture(in.SelfDisco))
	req, ok := capturedDiscovery(good, 1, in)
	if !ok || req.Direction != "out" || !bytes.Equal(req.Packet, discoFixture(in.SelfDisco)) {
		t.Fatal("valid native bootstrap was lost")
	}
	badSource := captureFixture(in, netip.MustParseAddrPort("192.0.2.1:41642"), in.Peers[0], discoFixture(in.SelfDisco))
	badKey := captureFixture(in, in.Native, in.Peers[0], discoFixture([32]byte{3}))
	wrongPeer := captureFixture(in, in.Native, netip.MustParseAddrPort("203.0.113.3:41641"), discoFixture(in.SelfDisco))
	fragment := append([]byte(nil), good...)
	fragment[14+6] = 0x20
	wrongLength := append([]byte(nil), good...)
	wrongLength[14+20+5]--
	data := captureFixture(in, in.Native, in.Peers[0], append([]byte{4, 0, 0, 0}, make([]byte, 32)...))
	for i, frame := range [][]byte{good[:20], good[:len(good)-1], badSource, badKey, wrongPeer, fragment, wrongLength, data} {
		if _, ok := capturedDiscovery(frame, 1, in); ok {
			t.Fatal("unsafe/truncated frame copied", i)
		}
	}
	// No allocation follows an attacker-controlled record length.
	var pcap bytes.Buffer
	header := make([]byte, 24)
	copy(header, []byte{0xd4, 0xc3, 0xb2, 0xa1})
	binary.LittleEndian.PutUint32(header[16:20], 2048)
	binary.LittleEndian.PutUint32(header[20:24], 1)
	pcap.Write(header)
	record := make([]byte, 16)
	binary.LittleEndian.PutUint32(record[8:12], 1<<30)
	pcap.Write(record)
	if err := readPCAP(&pcap, in, func(Injection) { t.Fatal("oversized pcap delivered a packet") }); err == nil {
		t.Fatal("oversized pcap accepted")
	}
}
