package kcp

import "net"

// ListenerSessionMismatchCallBackType is invoked when a packet cannot be
// matched to an existing session.
type ListenerSessionMismatchCallBackType func(addr net.Addr, conv uint32)
type TSessionMismatch = ListenerSessionMismatchCallBackType

type SessionUUID [16]byte

const (
	typeSessionControl     uint16 = 0xf4
	sessionControlMismatch uint8  = 1
	sessionControlReport   uint8  = 2
	sessionControlRecover  uint8  = 3
)

type SessionMismatchEvent struct {
	Addr       net.Addr
	Conv       uint32
	Generation uint32
}

type SessionMismatchCallback func(*SessionMismatchEvent)
type SessionRecoverCallback func(uuid SessionUUID, generation uint32)
