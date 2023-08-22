package go_mtr

import (
	"time"

	"golang.org/x/sys/unix"
)

type Config struct {
	ICMP            bool
	TCP             bool
	UDP             bool
	MaxUnReply      int
	NextHopWait     time.Duration
	RcvGoroutineNum int
	ErrCh           chan error
	BatchSize       int
}

type Trace struct {
	IsIpv4      bool          `json:"-"`
	SrcAddr     string        `json:"src_addr"`
	DstAddr     string        `json:"dst_addr"`
	SrcSockAddr unix.Sockaddr `json:"-"`
	DstSockAddr unix.Sockaddr `json:"-"`
	SrcPort     uint16        `json:"src_port"`
	DstPort     uint16        `json:"dst_port"`
	MaxTTL      uint8         `json:"max_ttl"`
	Retry       int           `json:"retry"`
}

type TraceRes struct {
	SrcTTL     string        `json:"src_ttl"`
	Latency    time.Duration `json:"latency"`
	TTL        uint8         `json:"ttl"`
	Reached    bool          `json:"reached"`
	PacketLoss float32       `json:"packet_loss"`
}
