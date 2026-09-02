// The MIT License (MIT)
//
// Copyright (c) 2015 xtaci
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package kcp

import (
	"container/heap"
	"encoding/binary"
	"io"
	"log/slog"
	"math"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/xtaci/lossyconn"
)

const repeat = 16

func TestLossyConn1(t *testing.T) {
	t.Log("testing loss rate 10%, rtt 200ms")
	t.Log("testing link with nodelay parameters:1 10 2 1")
	client, err := lossyconn.NewLossyConn(0.1, 100)
	if err != nil {
		t.Fatal(err)
		return
	}

	server, err := lossyconn.NewLossyConn(0.1, 100)
	if err != nil {
		t.Fatal(err)
		return
	}
	testlink(t, client, server, 1, 10, 2, 1)
}

func TestLossyConn2(t *testing.T) {
	t.Log("testing loss rate 20%, rtt 200ms")
	t.Log("testing link with nodelay parameters:1 10 2 1")
	client, err := lossyconn.NewLossyConn(0.2, 100)
	if err != nil {
		t.Fatal(err)
		return
	}

	server, err := lossyconn.NewLossyConn(0.2, 100)
	if err != nil {
		t.Fatal(err)
		return
	}
	testlink(t, client, server, 1, 10, 2, 1)
}

func TestLossyConn3(t *testing.T) {
	t.Log("testing loss rate 30%, rtt 200ms")
	t.Log("testing link with nodelay parameters:1 10 2 1")
	client, err := lossyconn.NewLossyConn(0.3, 100)
	if err != nil {
		t.Fatal(err)
		return
	}

	server, err := lossyconn.NewLossyConn(0.3, 100)
	if err != nil {
		t.Fatal(err)
		return
	}
	testlink(t, client, server, 1, 10, 2, 1)
}

func TestLossyConn4(t *testing.T) {
	t.Log("testing loss rate 10%, rtt 200ms")
	t.Log("testing link with nodelay parameters:1 10 2 0")
	client, err := lossyconn.NewLossyConn(0.1, 100)
	if err != nil {
		t.Fatal(err)
		return
	}

	server, err := lossyconn.NewLossyConn(0.1, 100)
	if err != nil {
		t.Fatal(err)
		return
	}
	testlink(t, client, server, 1, 10, 2, 0)
}

func testlink(t *testing.T, client *lossyconn.LossyConn, server *lossyconn.LossyConn, nodelay, interval, resend, nc int) {
	t.Log("testing with nodelay parameters:", nodelay, interval, resend, nc)
	sess, _ := NewConn2(server.LocalAddr(), nil, 0, 0, client)
	listener, _ := ServeConn(nil, 0, 0, server)
	echoServer := func(l *Listener) {
		for {
			conn, err := l.AcceptKCP()
			if err != nil {
				return
			}
			go func() {
				conn.SetNoDelay(nodelay, interval, resend, nc)
				buf := make([]byte, 65536)
				for {
					n, err := conn.Read(buf)
					if err != nil {
						return
					}
					conn.Write(buf[:n])
				}
			}()
		}
	}

	echoTester := func(s *UDPSession) {
		s.SetNoDelay(nodelay, interval, resend, nc)
		buf := make([]byte, 64)
		var rtt time.Duration
		for range repeat {
			start := time.Now()
			s.Write(buf)
			io.ReadFull(s, buf)
			rtt += time.Since(start)
		}

		t.Log("client:", client)
		t.Log("server:", server)
		t.Log("avg rtt:", rtt/repeat)
		t.Logf("total time: %v for %v round trip:", rtt, repeat)
	}

	go echoServer(listener)
	echoTester(sess)
}

func BenchmarkFlush(b *testing.B) {
	kcp := NewKCP(1, func(buf []byte, size int) {})
	kcp.snd_buf = NewRingBuffer[segment](1024)
	for range kcp.snd_buf.MaxLen() {
		kcp.snd_buf.Push(segment{xmit: 1, resendts: currentMs() + 10000})
	}

	b.ReportAllocs()
	var mu sync.Mutex
	for b.Loop() {
		mu.Lock()
		kcp.flush(IKCP_FLUSH_FULL)
		mu.Unlock()
	}
}

func TestParseAckDirectIndexWithSequenceWrap(t *testing.T) {
	kcp := NewKCP(1, func([]byte, int) {})
	kcp.snd_buf = NewRingBuffer[segment](8)
	kcp.snd_una = math.MaxUint32 - 2
	kcp.snd_nxt = 2

	sequenceNumbers := []uint32{math.MaxUint32 - 2, math.MaxUint32 - 1, math.MaxUint32, 0, 1}
	for _, sn := range sequenceNumbers {
		kcp.snd_buf.Push(segment{sn: sn})
	}

	kcp.parse_ack(0)
	for i, sn := range sequenceNumbers {
		seg, ok := kcp.snd_buf.At(i)
		if !ok {
			t.Fatalf("missing segment at index %d", i)
		}
		want := uint32(0)
		if sn == 0 {
			want = 1
		}
		if seg.acked != want {
			t.Fatalf("segment %d acked=%d, want %d", sn, seg.acked, want)
		}
	}

	// Old, future, and duplicate ACKs must not affect another segment.
	kcp.parse_ack(math.MaxUint32 - 3)
	kcp.parse_ack(2)
	kcp.parse_ack(0)
	for i, sn := range sequenceNumbers {
		seg, _ := kcp.snd_buf.At(i)
		if (sn == 0) != (seg.acked == 1) {
			t.Fatalf("unexpected ACK state for segment %d: %d", sn, seg.acked)
		}
	}
}

func TestInputAggregatesFastAckPerDatagram(t *testing.T) {
	kcp := newFastAckTestKCP(6, 100)
	packet := appendAck(nil, kcp.conv, 3, 100, 0)
	packet = appendAck(packet, kcp.conv, 5, 100, 0)

	if ret := kcp.Input(packet, IKCP_PACKET_FEC, false); ret != 0 {
		t.Fatalf("Input returned %d", ret)
	}
	kcp.applyFastAcks()

	for i := range 6 {
		seg, _ := kcp.snd_buf.At(i)
		wantFastAck := uint32(0)
		if i < 5 {
			wantFastAck = 1
		}
		if seg.fastack != wantFastAck {
			t.Fatalf("segment %d fastack=%d, want %d", i, seg.fastack, wantFastAck)
		}
	}
}

func TestInputKeepsTimestampPairedWithMaxAck(t *testing.T) {
	kcp := newFastAckTestKCP(6, 200)
	packet := appendAck(nil, kcp.conv, 5, 100, 0)
	packet = appendAck(packet, kcp.conv, 4, 300, 0)

	if ret := kcp.Input(packet, IKCP_PACKET_FEC, false); ret != 0 {
		t.Fatalf("Input returned %d", ret)
	}
	kcp.applyFastAcks()

	for i := range 6 {
		seg, _ := kcp.snd_buf.At(i)
		if seg.fastack != 0 {
			t.Fatalf("segment %d fastack=%d, want 0", i, seg.fastack)
		}
	}
}

func TestApplyFastAcksMatchesScalarAlgorithm(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for iteration := range 100 {
		const segmentCount = 257
		baseSN := uint32(math.MaxUint32 - 128 + iteration)
		baseTS := uint32(math.MaxUint32 - 500 + iteration)
		kcp := NewKCP(1, func([]byte, int) {})
		kcp.snd_buf = NewRingBuffer[segment](segmentCount + 1)
		kcp.snd_una = baseSN
		kcp.snd_nxt = baseSN + segmentCount

		expected := make([]uint32, segmentCount)
		for i := range segmentCount {
			fastack := uint32(rng.Intn(4))
			if i%41 == 0 {
				fastack = math.MaxUint32
			}
			ts := baseTS + uint32(rng.Intn(1000))
			kcp.snd_buf.Push(segment{sn: baseSN + uint32(i), ts: ts, fastack: fastack})
			expected[i] = fastack
		}

		for range 173 {
			ack := ackItem{
				sn: baseSN + uint32(rng.Intn(segmentCount)),
				ts: baseTS + uint32(rng.Intn(1000)),
			}
			kcp.fastackEvents = append(kcp.fastackEvents, ack)
			for i := range segmentCount {
				seg, _ := kcp.snd_buf.At(i)
				if expected[i] != math.MaxUint32 &&
					_itimediff(ack.sn, seg.sn) > 0 && _itimediff(seg.ts, ack.ts) <= 0 {
					expected[i]++
				}
			}
		}

		kcp.applyFastAcks()
		if len(kcp.fastackEvents) != 0 {
			t.Fatalf("iteration %d left %d pending fast ACKs", iteration, len(kcp.fastackEvents))
		}
		for i, want := range expected {
			seg, _ := kcp.snd_buf.At(i)
			if seg.fastack != want {
				t.Fatalf("iteration %d segment %d fastack=%d, want %d", iteration, i, seg.fastack, want)
			}
		}
	}
}

func TestWindowFlushOnlyVisitsNewSegments(t *testing.T) {
	var sent []uint32
	kcp := NewKCP(1, func(buf []byte, size int) {
		for len(buf) >= IKCP_OVERHEAD && size >= IKCP_OVERHEAD {
			length := int(binary.LittleEndian.Uint32(buf[20:]))
			segmentSize := IKCP_OVERHEAD + length
			if segmentSize > size || segmentSize > len(buf) {
				t.Fatalf("invalid output segment size %d", segmentSize)
			}
			if buf[4] == IKCP_CMD_PUSH {
				sent = append(sent, binary.LittleEndian.Uint32(buf[12:]))
			}
			buf = buf[segmentSize:]
			size -= segmentSize
		}
	})
	kcp.nocwnd = 1
	kcp.snd_wnd = 4
	kcp.rmt_wnd = 4
	kcp.snd_una = 0
	kcp.snd_nxt = 2
	kcp.snd_buf.Push(segment{sn: 0, xmit: 1, resendts: 0})
	kcp.snd_buf.Push(segment{sn: 1, xmit: 1, resendts: 0})
	kcp.snd_queue.Push(segment{})
	kcp.snd_queue.Push(segment{})

	kcp.flush(ikcpFlushWindow)

	if len(sent) != 2 || sent[0] != 2 || sent[1] != 3 {
		t.Fatalf("sent sequence numbers %v, want [2 3]", sent)
	}
	for i, wantXmit := range []uint32{1, 1, 1, 1} {
		seg, _ := kcp.snd_buf.At(i)
		if seg.xmit != wantXmit {
			t.Fatalf("segment %d xmit=%d, want %d", i, seg.xmit, wantXmit)
		}
	}
}

func TestDeferredFastAckTriggersRetransmit(t *testing.T) {
	var sent []uint32
	kcp := NewKCP(1, func(buf []byte, size int) {
		for len(buf) >= IKCP_OVERHEAD && size >= IKCP_OVERHEAD {
			length := int(binary.LittleEndian.Uint32(buf[20:]))
			segmentSize := IKCP_OVERHEAD + length
			if buf[4] == IKCP_CMD_PUSH {
				sent = append(sent, binary.LittleEndian.Uint32(buf[12:]))
			}
			buf = buf[segmentSize:]
			size -= segmentSize
		}
	})
	kcp.fastresend = 2
	kcp.nocwnd = 1
	kcp.snd_una = 0
	kcp.snd_nxt = 3
	kcp.snd_buf = NewRingBuffer[segment](4)
	for sn := range 3 {
		kcp.snd_buf.Push(segment{
			conv:     kcp.conv,
			cmd:      IKCP_CMD_PUSH,
			sn:       uint32(sn),
			ts:       100,
			xmit:     1,
			resendts: currentMs() + 60_000,
		})
	}

	packet := appendAck(nil, kcp.conv, 2, 100, 0)
	if ret := kcp.Input(packet, IKCP_PACKET_FEC, false); ret != 0 {
		t.Fatalf("first Input returned %d", ret)
	}
	if ret := kcp.Input(packet, IKCP_PACKET_FEC, false); ret != 0 {
		t.Fatalf("second Input returned %d", ret)
	}
	if len(sent) != 0 {
		t.Fatalf("Input sent retransmissions before the timer flush: %v", sent)
	}

	kcp.applyFastAcks()
	for i := range 2 {
		seg, _ := kcp.snd_buf.At(i)
		if seg.fastack != 2 {
			t.Fatalf("segment %d fastack=%d, want 2", i, seg.fastack)
		}
	}
	kcp.flush(IKCP_FLUSH_FULL)
	for i := range 2 {
		seg, _ := kcp.snd_buf.At(i)
		if seg.xmit != 2 {
			t.Fatalf("segment %d xmit=%d after flush, want 2", i, seg.xmit)
		}
	}
	if len(sent) != 2 || sent[0] != 0 || sent[1] != 1 {
		t.Fatalf("retransmitted sequence numbers %v, want [0 1]", sent)
	}
}

func BenchmarkParseAck(b *testing.B) {
	for _, size := range []int{4096, 18000, 36000} {
		b.Run(stringSize(size), func(b *testing.B) {
			kcp := newFastAckTestKCP(size, 100)
			target := uint32(size - 1)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				kcp.parse_ack(target)
			}
		})
	}
}

func BenchmarkInputAckBatch18K(b *testing.B) {
	kcp := newFastAckTestKCP(18000, 100)
	kcp.fastresend = math.MaxInt32
	packet := make([]byte, 0, 58*IKCP_OVERHEAD)
	for sn := uint32(17942); sn < 18000; sn++ {
		packet = appendAck(packet, kcp.conv, sn, 100, 0)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if ret := kcp.Input(packet, IKCP_PACKET_FEC, false); ret != 0 {
			b.Fatalf("Input returned %d", ret)
		}
		kcp.fastackEvents = kcp.fastackEvents[:0]
	}
}

func BenchmarkApplyFastAcks18K(b *testing.B) {
	kcp := newFastAckTestKCP(18000, 100)
	events := make([]ackItem, 100)
	for i := range events {
		events[i] = ackItem{sn: uint32(17900 + i), ts: 100}
	}
	// Warm the reusable sorting and Fenwick buffers before measuring.
	kcp.fastackEvents = append(kcp.fastackEvents, events...)
	kcp.applyFastAcks()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		kcp.fastackEvents = append(kcp.fastackEvents, events...)
		kcp.applyFastAcks()
	}
}

func newFastAckTestKCP(size int, ts uint32) *KCP {
	kcp := NewKCP(1, func([]byte, int) {})
	kcp.snd_buf = NewRingBuffer[segment](size + 1)
	kcp.snd_una = 0
	kcp.snd_nxt = uint32(size)
	kcp.fastresend = 10
	for sn := range size {
		kcp.snd_buf.Push(segment{sn: uint32(sn), ts: ts})
	}
	return kcp
}

func appendAck(dst []byte, conv, sn, ts, una uint32) []byte {
	start := len(dst)
	dst = append(dst, make([]byte, IKCP_OVERHEAD)...)
	binary.LittleEndian.PutUint32(dst[start:], conv)
	dst[start+4] = IKCP_CMD_ACK
	binary.LittleEndian.PutUint16(dst[start+6:], uint16(IKCP_WND_RCV))
	binary.LittleEndian.PutUint32(dst[start+8:], ts)
	binary.LittleEndian.PutUint32(dst[start+12:], sn)
	binary.LittleEndian.PutUint32(dst[start+16:], una)
	return dst
}

func stringSize(size int) string {
	switch size {
	case 4096:
		return "4K"
	case 18000:
		return "18K"
	case 36000:
		return "36K"
	default:
		panic("unexpected benchmark size")
	}
}

// TestSegmentHeap tests the segmentHeap data structure
func TestSegmentHeap(t *testing.T) {
	h := newSegmentHeap()
	segments := []segment{
		{sn: 1},
		{sn: 2},
		{sn: 3},
	}

	for _, seg := range segments {
		heap.Push(h, seg)
		t.Logf("pushed segment with seq %d", seg.sn)
	}

	if h.Len() != len(segments) {
		t.Errorf("expected length %d, got %d", len(segments), h.Len())
	}

	for i := range segments {
		seg := heap.Pop(h).(segment)
		if seg.sn != segments[i].sn {
			t.Errorf("expected seq %d, got %d", segments[i].sn, seg.sn)
		}
	}
}

// BenchmarkDebugLog test DebugLog cost time with build tags debug on/off
// trace log on:
//
//	go test -benchmem -run=^$ -bench ^BenchmarkDebugLog$ -tags debug
//
// trace log off:
func TestSetMtuBoundary(t *testing.T) {
	kcp := NewKCP(0, func(buf []byte, size int) {})

	tests := []struct {
		name string
		mtu  int
		want int // 0 = success, -1 = failure
	}{
		{"negative", -1, -1},
		{"zero", 0, -1},
		{"below overhead", IKCP_OVERHEAD - 1, -1},
		{"equal overhead", IKCP_OVERHEAD, -1},
		{"one above overhead (minimum valid)", IKCP_OVERHEAD + 1, 0},
		{"typical MTU", 1400, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := kcp.SetMtu(tt.mtu)
			if got != tt.want {
				t.Errorf("SetMtu(%d) = %d, want %d", tt.mtu, got, tt.want)
			}
		})
	}

	// verify mss is correctly derived after a valid SetMtu
	kcp.SetMtu(1400)
	if kcp.mss != 1400-IKCP_OVERHEAD {
		t.Errorf("mss = %d, want %d", kcp.mss, 1400-IKCP_OVERHEAD)
	}

	// minimum valid MTU yields mss = 1
	kcp.SetMtu(IKCP_OVERHEAD + 1)
	if kcp.mss != 1 {
		t.Errorf("mss = %d, want 1 for minimum valid MTU", kcp.mss)
	}
}

// go test -benchmem -run=^$ -bench ^BenchmarkDebugLog$
func BenchmarkDebugLog(b *testing.B) {
	kcp := &KCP{
		conv:    123,
		snd_wnd: 456,
	}
	kcp.log = slog.Debug

	for b.Loop() {
		// In release mode, this line of code will be completely 'erased' by the compiler,
		// as if it doesn't exist at all, and even the parameter's interface conversion will not occur.
		kcp.debugLog(IKCP_LOG_OUT_WASK, "conv", kcp.conv, "wnd", kcp.snd_wnd)
	}
}
