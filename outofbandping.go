package kcp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// BfUdpPingHead 是 out-of-band ping 包的 8 字节固定头部标识。
// 用于在 packetInput 中快速识别 ping 包，与 KCP/FEC 包区分开。
// 选择 0xaa 0xbb 0xcc 0xdd 重复两次，是因为这个模式不会与 KCP 的
// conv/cmd/frg 字段或 FEC 的 type 标记（0xf1/0xf2/0xf3）冲突。
var BfUdpPingHead = []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xaa, 0xbb, 0xcc, 0xdd}

// reconnectLogInterval 限制重连日志的输出频率，同一个地址每 5 秒最多一条。
//
// 为什么需要限频：在网络抖动或 NAT 端口频繁切换的场景下，客户端可能短时间内
// 发送大量重连包。如果每次都输出日志，会产生大量重复输出，既影响性能又
// 淹没真正有用的信息。5 秒间隔足够观察到重连事件，同时避免日志风暴。
const reconnectLogInterval = 5 * time.Second

// reconnectLogMap 记录每个地址上次输出重连日志的时间。
// 使用 sync.Map 而不是 mutex+map，因为：
// 1. 读多写少场景下 sync.Map 性能更好
// 2. 无锁读路径不会阻塞 packetInput 的正常处理
// 3. 不需要额外定义 mutex 字段
var reconnectLogMap sync.Map // key: addr string, value: time.Time

// shouldLogReconnect 检查是否应该输出重连日志（同一个地址每 5 秒最多一条）。
//
// 调用场景：Listener.packetInput 中处理重连逻辑时，在输出 "fast recover
// reconnect" 或 "packetInput ignored" 日志前调用。
//
// 返回 true 表示可以输出日志，同时更新该地址的最后日志时间；
// 返回 false 表示距上次输出不足 5 秒，应跳过本次日志。
func shouldLogReconnect(addrStr string) bool {
	now := time.Now()
	if last, ok := reconnectLogMap.Load(addrStr); ok {
		if last.(time.Time).Add(reconnectLogInterval).After(now) {
			return false
		}
	}
	reconnectLogMap.Store(addrStr, now)
	return true
}

// PktUdpPing* 是预构造的 ping 包模板，共 16 字节。
// 包格式：| BfUdpPingHead (8B) | Dmrid (4B) | LoginType (1B) | Cmd (1B) | Seq (2B) |
// Cmd 值区分不同 ping 类型：1=ping, 2=pong, 4=探测, 8=重连触发。
// PktUdpPing8 (cmd=8) 专门用于触发对端重连，由 BfSendUdpPing8 发送。
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

// TudpPing 是解析后的 out-of-band ping 包结构。
// 用户通过 FnOutOfBandPing 回调接收此结构，可调用 Migrate2Session
// 等方法执行 session 迁移或发送回复 ping。
type TudpPing struct {
	Dmrid     uint32      // 设备/用户 ID（由发送方填充）
	LoginType uint8       // 登录类型标识
	Cmd       uint8       // ping 命令类型：1=ping, 2=pong, 4=探测, 8=重连触发
	Seq       uint16      // 序列号
	Addr      net.Addr    // 发送方地址（用于回复）
	Session   *UDPSession // 关联的 session（Listener 端可能为 nil）
	Listener  *Listener   // 关联的 Listener（Client 端为 nil）
}

// TOutOfBandPing 是用户注册的 out-of-band ping 回调函数类型。
// 设置在 UDPSession.FnOutOfBandPing 或 Listener.FnOutOfBandPing 上。
type TOutOfBandPing = func(pkt *TudpPing)

// Migrate2Session 将 session s 的远端地址从旧地址迁移到 ping 包来源地址。
//
// 使用场景：客户端 NAT 端口切换后，旧 session 仍然有效但地址已变。
// 用户在 FnOutOfBandPing 回调中收到 ping 包后调用此方法，将旧 session
// 迁移到新地址，避免重新建连的开销。
//
// 迁移逻辑：
// 1. 如果新地址上已有 session，先把它移到旧地址（交换），然后关闭它
// 2. 把 s 的 remote 改为新地址，更新 sessions map
// 3. 设置 newSession.l = nil 防止 Close 时再次操作 Listener
func (this *TudpPing) Migrate2Session(s *UDPSession) {
	if this.Session == s {
		fmt.Println("Migrate2Session: newSession == oldSession")
		return
	}
	if this.Listener == nil {
		return
	}
	oldAddr := s.RemoteAddr()
	oldAddrStr := oldAddr.String()
	oldSession := s
	newAddr := this.Addr
	newAddrStr := newAddr.String()

	if oldAddrStr == newAddrStr {
		return
	}

	this.Listener.sessionLock.Lock()
	newSession, newOK := this.Listener.sessions[newAddrStr]
	if newOK {
		if newSession == oldSession {
			fmt.Println("Migrate2Session: newSession == oldSession")
			this.Listener.sessionLock.Unlock()
			return
		}
		newSession.remote = oldAddr
	}

	oldSession.remote = newAddr
	delete(this.Listener.sessions, oldAddrStr)
	this.Listener.sessions[newAddrStr] = s

	this.Listener.sessionLock.Unlock()

	if newOK && newSession != oldSession {
		newSession.l = nil
		_ = newSession.Close()
	}
}

// SendPing1/2/4 通过 Listener 的连接发送对应类型的 ping 包到 ping 来源地址。
// 这些方法在用户回调中调用，用于回复 ping 或主动探测。
func (this *TudpPing) SendPing1() {
	_, _ = this.Listener.conn.WriteTo(PktUdpPing1, this.Addr)
}
func (this *TudpPing) SendPing2() {
	_, _ = this.Listener.conn.WriteTo(PktUdpPing2, this.Addr)
}
func (this *TudpPing) SendPing4() {
	_, _ = this.Listener.conn.WriteTo(PktUdpPing4, this.Addr)
}

// ClientOutOfBandPing 处理客户端收到的 16 字节 ping 包。
//
// 调用路径：UDPSession.packetInput -> go ClientOutOfBandPing(dataCopy, s)
// 注意：data 必须是 copy 后的独立 buffer，因为 packetInput 的 data 指向
// readLoop 的复用 buffer，异步 goroutine 不能直接引用原 buffer。
//
// 如果用户未设置 FnOutOfBandPing 回调，或包头部不匹配，直接返回不做处理。
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

// ListenerOutOfBandPing 处理 Listener 端收到的 16 字节 ping 包。
//
// 调用路径：Listener.packetInput -> go ListenerOutOfBandPing(dataCopy, addr, l)
// 与 ClientOutOfBandPing 类似，data 必须是 copy 后的独立 buffer。
//
// Listener 端会根据来源地址查找对应的 session，如果找不到则 Session 为 nil。
// 用户可以在回调中通过 pktPing.Session 判断是否已有 session，并决定
// 是否调用 Migrate2Session 进行迁移。
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

// BfSendUdpPing8 向指定地址发送 cmd=8 的 ping 包（重连触发包）。
//
// 调用场景：Listener.packetInput 中，当收到来自未知地址的非新连接包时，
// 通过 go BfSendUdpPing8(l, addr) 异步发送。客户端收到后会触发
// FnOutOfBandPing 回调，可在回调中执行重连逻辑。
//
// 使用 go 异步发送是为了不阻塞 packetInput 的主处理流程。
func BfSendUdpPing8(l *Listener, addr net.Addr) {
	_, _ = l.conn.WriteTo(PktUdpPing8, addr)
}
