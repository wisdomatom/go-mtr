package go_mtr

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func mockTrace() []Trace {
	var data []Trace
	var dataT = []Trace{
		{
			SrcAddr: GetOutbondIP(),
			DstAddr: "8.8.8.8",
			SrcPort: 65523,
			DstPort: 65535,
			MaxTTL:  60,
			Retry:   2,
		},
	}
	for idx := range dataT {
		d, err := GetTrace(&dataT[idx])
		if err != nil {
			continue
		}
		data = append(data, *d)
	}
	return data
}

func TestTrace(t *testing.T) {
	tr, err := NewTrace(Config{
		//UDP: true,
		ICMP:        true,
		MaxUnReply:  8,
		NextHopWait: time.Millisecond * 100,
	})
	if err != nil {
		panic(err)
	}
	tc, err := GetTrace(&Trace{
		SrcAddr: GetOutbondIP(),
		DstAddr: "8.8.8.8",
		SrcPort: 65523,
		DstPort: 65535,
		MaxTTL:  60,
		Retry:   2,
	})
	if err != nil {
		panic(err)
	}
	err = tr.Listen()
	if err != nil {
		panic(err)
	}
	defer tr.Close()
	res := tr.BatchTrace([]Trace{
		*tc,
	}, 1)
	for _, r := range res {
		fmt.Println(r.Marshal())
		fmt.Println("===================================================")
		fmt.Println(r.MarshalAggregate())
	}
}

func TestTraceBatch(t *testing.T) {
	tr, err := NewTrace(Config{
		//UDP: true,
		ICMP:        true,
		MaxUnReply:  8,
		NextHopWait: time.Millisecond * 100,
	})
	if err != nil {
		panic(err)
	}
	err = tr.Listen()
	if err != nil {
		panic(err)
	}
	defer tr.Close()
	wg := sync.WaitGroup{}
	batch := mockTrace()
	for i := 0; i < 1; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				res := tr.BatchTrace(batch, 60)
				for _, r := range res {
					fmt.Println(r.Marshal())
				}
				time.Sleep(time.Second * 2)
			}
		}()
	}
	wg.Wait()
}
