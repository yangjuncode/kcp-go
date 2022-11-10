package kcp

import (
	"bytes"
	"encoding/binary"
	"net"
)

var BfUdpPingHead = []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xaa, 0xbb, 0xcc, 0xdd}

var PktUdpPing1 = []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xaa, 0xbb, 0xcc, 0xdd,
	0x00, 0x00, 0x00, 0x00,
	99, 1, 0, 0}
var PktUdpPing2 = []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xaa, 0xbb, 0xcc, 0xdd,
	0x00, 0x00, 0x00, 0x00,
	99, 2, 0, 0}
var PktUdpPing4 = []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xaa, 0xbb, 0xcc, 0xdd,
	0x00, 0x00, 0x00, 0x00,
	99, 4, 0, 0}
var PktUdpPing8 = []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xaa, 0xbb, 0xcc, 0xdd,
	0x00, 0x00, 0x00, 0x00,
	99, 8, 0, 0}

type TudpPing struct {
	Dmrid     uint32
	LoginType uint8
	Cmd       uint8
	Seq       uint16
	Addr      net.Addr
	Session   *UDPSession
	Listener  *Listener
}

type TOutOfBandPing = func(pkt *TudpPing)

func (this *TudpPing) Migrate2Session(s *UDPSession) {
	if this.Listener == nil {
		return
	}
	oldAddr := s.RemoteAddr()
	oldAddrStr := oldAddr.String()
	oldSession := s
	newAddr := this.Addr
	newAddrStr := newAddr.String()

	this.Listener.sessionLock.Lock()
	newSession, newOK := this.Listener.sessions[newAddrStr]
	if newOK {
		newSession.remote = oldAddr
	}

	oldSession.remote = newAddr
	this.Listener.sessions[newAddrStr] = s
	delete(this.Listener.sessions, oldAddrStr)

	this.Listener.sessionLock.Unlock()

	if newOK {
		_ = newSession.Close()
	}
}
func (this *TudpPing) SendPing1() {
	_, _ = this.Listener.conn.WriteTo(PktUdpPing1, this.Addr)
}
func (this *TudpPing) SendPing2() {
	_, _ = this.Listener.conn.WriteTo(PktUdpPing2, this.Addr)
}
func (this *TudpPing) SendPing4() {
	_, _ = this.Listener.conn.WriteTo(PktUdpPing4, this.Addr)
}
func ClientOutOfBandPing(data []byte, s *UDPSession) {
	if s.FnOutOfBandPing == nil {
		return
	}
	if !bytes.HasPrefix(data, BfUdpPingHead) {
		return
	}

	pktPing := &TudpPing{
		Dmrid:     binary.LittleEndian.Uint32(data[8:]),
		LoginType: data[12],
		Cmd:       data[13],
		Seq:       binary.LittleEndian.Uint16(data[14:]),
		Addr:      s.RemoteAddr(),
		Session:   s,
		Listener:  nil,
	}

	s.FnOutOfBandPing(pktPing)
}
func ListenerOutOfBandPing(data []byte, addr net.Addr, l *Listener) {
	if !bytes.HasPrefix(data, BfUdpPingHead) {
		return
	}
	if l.FnOutOfBandPing == nil {
		return
	}
	addrStr := addr.String()
	//bf8100 outof band ping
	l.sessionLock.RLock()
	s, _ := l.sessions[addrStr]
	l.sessionLock.RUnlock()

	pktPing := &TudpPing{
		Dmrid:     binary.LittleEndian.Uint32(data[8:]),
		LoginType: data[12],
		Cmd:       data[13],
		Seq:       binary.LittleEndian.Uint16(data[14:]),
		Addr:      addr,
		Session:   s,
		Listener:  l,
	}

	l.FnOutOfBandPing(pktPing)
}

func BfSendUdpPing8(l *Listener, addr net.Addr) {
	_, _ = l.conn.WriteTo(PktUdpPing8, addr)
}
