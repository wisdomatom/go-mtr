package go_mtr

import (
	"fmt"
	"testing"
	"time"
)

func TestTrace(t *testing.T) {
	tr, err := NewTrace(Config{
		UDP: true,
		//ICMP:        true,
		MaxUnReply:  8,
		NextHopWait: time.Millisecond * 100,
	})
	if err != nil {
		panic(err)
	}
	tc, err := GetTrace(&Trace{
		SrcAddr: "10.23.228.78",
		//SrcAddr: "172.16.57.12",
		DstAddr: "172.16.57.12",
		SrcPort: 65532,
		DstPort: 65535,
		MaxTTL:  30,
		Retry:   0,
	})
	if err != nil {
		panic(err)
	}
	go tr.Listen()
	defer tr.Close()
	res := tr.BatchTrace([]Trace{
		*tc,
	}, 30)
	for _, r := range res {
		fmt.Println(r.Marshal())
	}
}
