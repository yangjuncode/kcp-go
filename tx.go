package kcp

import (
	"sync/atomic"

	"github.com/pkg/errors"
	"golang.org/x/net/ipv4"
)

func (s *UDPSession) defaultTx(txqueue []ipv4.Message) {
	nbytes := 0
	npkts := 0
	for k := range txqueue {
		data := txqueue[k].Buffers[0]
		addr := txqueue[k].Addr
		//fmt.Println(time.Now().Format(time.StampMilli), "udp write to ", addr, " data:", hex.EncodeToString(data))
		if n, err := s.conn.WriteTo(data, addr); err == nil {
			nbytes += n
			npkts++
		} else {
			s.notifyWriteError(errors.WithStack(err))
			break
		}
	}
	atomic.AddUint64(&DefaultSnmp.OutPkts, uint64(npkts))
	atomic.AddUint64(&DefaultSnmp.OutBytes, uint64(nbytes))
}
