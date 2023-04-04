package go_mtr

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
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
	atomId        uint32
	conf          Config
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
	Id  uint16
	Key string
	Trace
	StartAt    time.Time
	Done       bool
	AvgPktLoss float32
	Res        []TraceRes
}

func (t TraceResult) Marshal() string {
	var line []string
	line = append(line, fmt.Sprintf("id:%-5d key:%-35v", t.Id, t.Key))
	for _, r := range t.Res {
		line = append(line, fmt.Sprintf("ttl:%-4d hop:%-16s src:%-16s dst:%-16s  latency:%-14v reached:%-6v",
			r.TTL,
			r.SrcTTL,
			t.SrcAddr,
			t.DstAddr,
			r.Latency.String(),
			r.Reached,
		))
	}
	line = append(line, fmt.Sprintf("pkg_loss:%6v", t.AvgPktLoss))
	if t.Done {
		line = append(line, fmt.Sprintf("trace successed!"))
	} else {
		line = append(line, fmt.Sprintf("trace failed!"))
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
		conf:          conf,
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

func (t *tracer) getAtomId() uint16 {
	n := atomic.AddUint32(&t.atomId, 1)
	return uint16(n % 65535)
}

func (t *tracer) tracerKey(id uint16, src string, srcPort uint16, dst string, dstPort uint16) string {
	if t.conf.UDP {
		key := fmt.Sprintf("%v:%v:%v-%v:%v", id, src, srcPort, dst, dstPort)
		return key
	}
	if t.conf.ICMP {
		key := fmt.Sprintf("%v:%v-%v", id, src, dst)
		return key
	}
	return fmt.Sprintf("%v:%v-%v", id, src, dst)
}

func (t *tracer) handleRcv(rcv *ICMPRcv) {
	key := t.tracerKey(rcv.Id, rcv.Src, rcv.SrcPort, rcv.Dst, rcv.DstPort)
	chI, ok := t.traceResChMap.Load(key)
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
	if len(batch) == 0 {
		return nil
	}
	var result []TraceResult
	ch := make(chan *TraceResult, len(batch))
	for idx, b := range batch {
		atomId := t.getAtomId()
		key := t.tracerKey(atomId, b.SrcAddr, b.SrcPort, b.DstAddr, b.DstPort)
		tr := TraceResult{
			Id:      atomId,
			Key:     key,
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
	ch := make(chan *ICMPRcv, 100)
	t.traceResChMap.Store(tc.Key, ch)
	defer t.traceResChMap.Delete(tc.Key)
	unReply := 0
	total := 0
	loss := 0
	for ttl := startTTL; ttl <= tc.MaxTTL; ttl++ {
		var pkg []byte
		total++
		start := time.Now()
		tc.MaxTTL = ttl
		if tc.IsIpv4 {
			pkg, err = t.ipv4.constructor.Packet(ConstructPacket{
				Trace:   tc.Trace,
				Id:      tc.Id,
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
				Id:      tc.Id,
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
				loss++
				if unReply >= t.maxUnReply {
					tc.AvgPktLoss = float32(loss) / float32(total)
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
					tc.AvgPktLoss = float32(loss) / float32(total)
					resCh <- tc
					return
				}
				if r.Reached {
					tc.Done = true
					tc.Res = append(tc.Res, r)
					tc.AvgPktLoss = float32(loss) / float32(total)
					resCh <- tc
					return
				}
				tc.Res = append(tc.Res, r)
				break For
			}
		}
	}
	if total > 0 {
		tc.AvgPktLoss = float32(loss) / float32(total)
	}
	resCh <- tc
	return
}
