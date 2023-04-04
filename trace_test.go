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
			SrcAddr: "10.23.228.52",
			DstAddr: "172.16.57.12",
			SrcPort: 65523,
			DstPort: 65535,
			MaxTTL:  60,
			Retry:   0,
		},
	}
	for idx, _ := range dataT {
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
		UDP: true,
		// ICMP:        true,
		MaxUnReply:  8,
		NextHopWait: time.Millisecond * 100,
	})
	if err != nil {
		panic(err)
	}
	tc, err := GetTrace(&Trace{
		SrcAddr: "172.16.57.12",
		DstAddr: "172.16.56.88",
		SrcPort: 65523,
		DstPort: 65535,
		MaxTTL:  60,
		Retry:   0,
	})
	if err != nil {
		panic(err)
	}
	go tr.Listen()
	defer tr.Close()
	res := tr.BatchTrace([]Trace{
		*tc,
	}, 1)
	for _, r := range res {
		fmt.Println(r.Marshal())
	}
}

func TestTraceBatch(t *testing.T) {
	tr, err := NewTrace(Config{
		UDP: true,
		//ICMP:        true,
		MaxUnReply:  8,
		NextHopWait: time.Millisecond * 100,
	})
	if err != nil {
		panic(err)
	}
	go tr.Listen()
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
