package go_mtr

import (
	"fmt"
	"sync"
	"time"
)

type Tracer interface {
}

type tracer struct {
	ipv4          *tracerIpv4
	ipv6          *tracerIpv6
	traceResChMap *sync.Map
}

type tracerIpv4 struct {
	constructor   Constructor
	deConstructor DeConstructor
	detector      Detector
	receiver      Receiver
}

type tracerIpv6 struct {
	constructor   Constructor
	deConstructor DeConstructor
	detector      Detector
	receiver      Receiver
}

type TraceResult struct {
	id string
	Trace
	StartAt time.Time
	Done    bool
	Res     []TraceRes
}

func NewTrace() Tracer {
	tc := &tracer{
		traceResChMap: &sync.Map{},
	}
	return tc
}

func (t *tracer) handleRcv(rcv *ICMPRcv) {
	id := fmt.Sprintf("%v-%v", rcv.Src, rcv.Dst)
	chI, ok := t.traceResChMap.Load(id)
	if !ok {
		return
	}
	ch := chI.(chan *ICMPRcv)
	ch <- rcv
}

func (t *tracer) Listen() {
	chIpv4 := t.ipv4.receiver.Receive()
	chIpv6 := t.ipv6.receiver.Receive()
	go func() {
		for {
			select {
			case msg := <-chIpv4:
				rcv, err := t.ipv4.deConstructor.DeConstruct(msg)
				if err != nil {
					continue
				}
				t.handleRcv(rcv)
			case msg := <-chIpv6:
				rcv, err := t.ipv6.deConstructor.DeConstruct(msg)
				if err != nil {
					continue
				}
				t.handleRcv(rcv)
			}
		}
	}()
}

func (t *tracer) Close() {
	t.ipv4.detector.Close()
	t.ipv4.receiver.Close()
	t.ipv6.detector.Close()
	t.ipv6.receiver.Close()
}

func (t *tracer) BatchTrace(batch []Trace) []TraceResult {
	var result []TraceResult
	ch := make(chan *TraceResult, len(batch))
	for idx, b := range batch {
		tr := TraceResult{
			id:      fmt.Sprintf("%v-%v", b.SrcAddr, b.DstAddr),
			Trace:   batch[idx],
			StartAt: time.Time{},
			Done:    false,
			Res:     []TraceRes{},
		}
		go t.trace(&tr, ch)
	}
	for {
		select {
		case r := <-ch:
			result = append(result, *r)
			if len(result) == len(batch) {
				return result
			}
		}
	}
}

func (t *tracer) trace(tc *TraceResult, resCh chan *TraceResult) {
	ch := make(chan *ICMPRcv)
	t.traceResChMap.Store(tc.id, ch)
	maxUnReply := 3
	unReply := 0
	for ttl := uint8(1); ttl <= tc.MaxTTL+4; ttl++ {
		start := time.Now()
		if tc.IsIpv4 {
			err := t.ipv4.detector.Probe(SendProbe{
				Trace:        tc.Trace,
				WriteTimeout: time.Duration(1) * time.Second,
			})
			if err != nil {
				continue
			}
		} else {
			err := t.ipv6.detector.Probe(SendProbe{
				Trace:        tc.Trace,
				WriteTimeout: time.Duration(1) * time.Second,
			})
			if err != nil {
				continue
			}
		}
		to := time.NewTimer(time.Millisecond * 700)
	For:
		for {
			select {
			case <-to.C:
				unReply++
				tc.Res = append(tc.Res, TraceRes{
					SrcTTL:  "",
					Latency: 0,
					TTL:     ttl,
					Reached: false,
				})
				break For
			case rcv := <-ch:
				unReply = 0
				r := TraceRes{
					SrcTTL:  rcv.TTLSrc,
					Latency: time.Now().Sub(start),
					TTL:     rcv.TTL,
					Reached: false,
				}
				if rcv.RcvType == ICMPEcho || rcv.RcvType == ICMPUnreachable {
					r.Reached = true
				}
				tc.Res = append(tc.Res, r)
				if r.Reached {
					tc.Done = true
					resCh <- tc
					return
				}
				if unReply >= maxUnReply {
					resCh <- tc
					return
				}
			}
		}
	}
	resCh <- tc
	return
}
