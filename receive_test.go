package go_mtr

import (
	"fmt"
	"testing"
)

func fmtICMPRcv(r *ICMPRcv) {
	fmt.Printf("%v %v %v %v %v %v %v\n", r.RcvType, r.TTLSrc, r.Src, r.Dst, r.Id, r.Seq, r.Reachable)
}

func TestReceive(t *testing.T) {
	cf := Config{}
	rcv, err := newRcvIpv4(cf)
	if err != nil {
		panic(err)
	}
	deCon := newDeconstructIpv4(cf)
	ch, err := rcv.Receive()
	if err != nil {
		t.Error(err)
		return
	}
	for {
		select {
		case bts := <-ch:
			icmp, err := deCon.DeConstruct(bts)
			if err != nil {
				continue
			}
			fmtICMPRcv(icmp)
		}
	}
}
