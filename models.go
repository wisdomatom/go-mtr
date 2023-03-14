package go_mtr

import "time"

type Config struct {
	ICMP bool
	TCP bool
	UDP bool
}

type Trace struct {
	SrcAddr string
	DstAddr string
	MaxTTL string
	Retry int


}

type TraceRes struct {
	Trace
	Latency time.Duration
	TTL int
	Reached bool
}
