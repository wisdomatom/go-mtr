package go_mtr

import (
	"golang.org/x/sys/unix"
	"time"
)

type Config struct {
	ICMP bool
	TCP  bool
	UDP  bool
}

type Trace struct {
	IsIpv4      bool
	SrcAddr     string
	DstAddr     string
	SrcSockAddr unix.Sockaddr
	DstSockAddr unix.Sockaddr
	SrcPort     int
	DstPort     int
	MaxTTL      uint8
	Retry       int
}

type TraceRes struct {
	SrcTTL  string
	Latency time.Duration
	TTL     uint8
	Reached bool
	//Err     error
	//Finish  bool
}