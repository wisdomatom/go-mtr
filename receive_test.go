package go_mtr

import (
	"fmt"
	"testing"
)

func fmtICMPRcv(r *ICMPRcv) {
	fmt.Printf("%v %v %v %v %v %v %v\n", r.RcvType, r.TTLSrc, r.Src, r.Dst, r.Id, r.Seq, r.Reachable)
}

func TestReceive(t *testing.T) {
	rcv, err := newRcvIpv4()
	if err != nil {
		panic(err)
	}
	deCon := newDeconstructIpv4()
	ch := rcv.Receive()
	for {
		select {
		case bts := <-ch:
			icmp, err := deCon.DeConstruct(bts)
			if err != nil {
				panic(err)
			}
			fmtICMPRcv(icmp)
		}
	}
}
