package go_mtr

import (
	"context"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	icmpV4TypeCodeMap = map[layers.ICMPv4TypeCode]string{
		layers.ICMPv4TypeDestinationUnreachable: ICMPUnreachable,
		layers.ICMPv4TypeTimeExceeded:           ICMPTimeExceed,
		layers.ICMPv4TypeEchoReply:              ICMPEcho,
	}
)

type rcvIpv4Bpf struct {
	Config
	ctx       context.Context
	handle    *pcap.Handle
	pktSource *gopacket.PacketSource
	cancel    func()
}

func newRcvIpv4Bpf(conf Config) (Receiver, error) {
	ctx, cancel := context.WithCancel(context.Background())
	r := &rcvIpv4Bpf{
		ctx:    ctx,
		cancel: cancel,
		Config: conf,
	}
	handle, err := pcap.OpenLive("any", 128, false, pcap.BlockForever)
	err = handle.SetBPFFilter("less 48 and (icmp[icmptype] == icmp-echoreply or icmp[icmptype] == icmp-unreach or icmp[icmptype] == icmp-timxceed)")
	if err != nil {
		return r, err
	}
	r.handle = handle
	pktSource := gopacket.NewPacketSource(r.handle, r.handle.LinkType())
	pktSource.Lazy = true
	pktSource.NoCopy = true
	r.pktSource = pktSource
	return r, nil
}

func (r *rcvIpv4Bpf) Receive() (chan *ICMPRcv, error) {
	ch := make(chan *ICMPRcv, 1024)
	go func() {
		pktCh := r.pktSource.Packets()
		for {
			select {
			case <-r.ctx.Done():
				r.Close()
				return
			case pkt := <-pktCh:
				icmpLayer := pkt.Layer(layers.LayerTypeICMPv4)
				if icmpLayer == nil {
					continue
				}
				icmpPkg := icmpLayer.(*layers.ICMPv4)

				ipv4Layer := pkt.Layer(layers.LayerTypeIPv4)
				if ipv4Layer == nil {
					continue
				}
				ipv4Pkg := ipv4Layer.(*layers.IPv4)

				rcv := &ICMPRcv{
					Id:        icmpPkg.Id,
					Seq:       icmpPkg.Seq,
					TTL:       ipv4Pkg.TTL,
					Src:       ipv4Pkg.SrcIP.String(),
					Dst:       ipv4Pkg.DstIP.String(),
					SrcPort:   0,
					DstPort:   0,
					RcvType:   icmpV4TypeCodeMap[icmpPkg.TypeCode],
					RcvAt:     time.Now(),
					Reachable: false,
				}
				if rcv.RcvType == ICMPTimeExceed {
					continue
				}
			}
		}
	}()
	return ch, nil
}

func (r *rcvIpv4Bpf) Close() {
	// r.handle.Close()
	// r.cancel()
}
