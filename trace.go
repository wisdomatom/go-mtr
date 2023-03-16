package go_mtr

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

type Tracer interface {
	Listen()
	Close()
	BatchTrace(batch []Trace, startTTL uint8) []TraceResult
}

type tracer struct {
	maxUnReply    int
	nextHopWait   time.Duration
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

func (t TraceResult) Marshal() string {
	var line []string
	for _, r := range t.Res {
		line = append(line, fmt.Sprintf("ttl:%v hop:%v src:%v dst:%v latency:%v reached:%v",
			r.TTL,
			r.SrcTTL,
			t.SrcAddr,
			t.DstAddr,
			r.Latency,
			r.Reached,
		))
	}
	return strings.Join(line, "\n")
}

func NewTrace(conf Config) (Tracer, error) {
	ipv4, err := tracerI4(conf)
	if err != nil {
		return nil, err
	}
	ipv6, err := tracerI6(conf)
	if err != nil {
		return nil, err
	}
	tc := &tracer{
		nextHopWait:   conf.NextHopWait,
		maxUnReply:    conf.MaxUnReply,
		ipv4:          ipv4,
		ipv6:          ipv6,
		traceResChMap: &sync.Map{},
	}
	return tc, nil
}

func tracerI4(conf Config) (*tracerIpv4, error) {
	con := newConstructIpv4(conf)
	deCon := newDeconstructIpv4()
	detector := newProbeIpv4()
	rcv, err := newRcvIpv4()
	if err != nil {
		return nil, err
	}
	return &tracerIpv4{
		constructor:   con,
		deConstructor: deCon,
		detector:      detector,
		receiver:      rcv,
	}, nil
}

func tracerI6(conf Config) (*tracerIpv6, error) {
	con := newConstructIpv6(conf)
	deCon := newDeconstructIpv6()
	detector := newProbeIpv6()
	rcv, err := newRcvIpv6()
	if err != nil {
		return nil, err
	}
	return &tracerIpv6{
		constructor:   con,
		deConstructor: deCon,
		detector:      detector,
		receiver:      rcv,
	}, nil
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

func (t *tracer) BatchTrace(batch []Trace, startTTL uint8) []TraceResult {
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
		go t.trace(startTTL, &tr, ch)
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

func (t *tracer) trace(startTTL uint8, tc *TraceResult, resCh chan *TraceResult) {
	var err error
	ch := make(chan *ICMPRcv)
	t.traceResChMap.Store(tc.id, ch)
	defer t.traceResChMap.Delete(tc.id)
	unReply := 0
	maxTTl := tc.MaxTTL
	for ttl := startTTL; ttl <= maxTTl+4; ttl++ {
		var pkg []byte
		start := time.Now()
		tc.MaxTTL = ttl
		if tc.IsIpv4 {
			pkg, err = t.ipv4.constructor.Packet(ConstructPacket{
				Trace:   tc.Trace,
				Id:      uint16(ttl),
				Seq:     uint16(ttl),
				SrcPort: tc.SrcPort,
				DstPort: tc.DstPort,
			})
			if err != nil {
				continue
			}
			err = t.ipv4.detector.Probe(SendProbe{
				Trace:        tc.Trace,
				WriteTimeout: time.Duration(1) * time.Second,
				Msg:          pkg,
			})
			if err != nil {
				continue
			}
		} else {
			pkg, err = t.ipv6.constructor.Packet(ConstructPacket{
				Trace:   tc.Trace,
				Id:      uint16(ttl),
				Seq:     uint16(ttl),
				SrcPort: tc.SrcPort,
				DstPort: tc.DstPort,
			})
			if err != nil {
				continue
			}
			err := t.ipv6.detector.Probe(SendProbe{
				Trace:        tc.Trace,
				WriteTimeout: time.Duration(1) * time.Second,
				Msg:          pkg,
			})
			if err != nil {
				continue
			}
		}
		to := time.NewTimer(t.nextHopWait)
	For:
		for {
			select {
			case <-to.C:
				unReply++
				if unReply >= t.maxUnReply {
					resCh <- tc
					return
				}
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
					tc.Done = true
					tc.Res = append(tc.Res, r)
					resCh <- tc
					return
				}
				if r.Reached {
					tc.Done = true
					tc.Res = append(tc.Res, r)
					resCh <- tc
					return
				}
				tc.Res = append(tc.Res, r)
				break For
			}
		}
	}
	resCh <- tc
	return
}
