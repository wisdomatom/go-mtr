package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	go_mtr "github.com/wisdomatom/go-mtr"
)

var (
	root *cobra.Command
)

func init() {
	root = &cobra.Command{
		Use:   "IP detect and route trace",
		Short: "IP detect and route trace",
		Run:   run,
	}
	cobra.OnInitialize()
	root.PersistentFlags().StringP("source", "s", "0.0.0.0", "source ip address, config which nic to send probe packet, 源IP")
	root.PersistentFlags().StringP("target", "t", "8.8.8.8", "target ip address, 目的IP")
	root.PersistentFlags().Uint16("source_port", 65533, "source port, 源端口")
	root.PersistentFlags().Uint16("target_port", 65535, "target port, 目的端口")
	root.PersistentFlags().IntP("retry", "r", 1, "how many times retry on each hop, 每跳ttl重试次数")
	root.PersistentFlags().Int("max_unreply", 8, "stop detect when max unreply packet exceeded, 最大连续丢包次数 判断不可达")
	root.PersistentFlags().String("type", "icmp", "detect type, icmp/udp proto")
	root.PersistentFlags().Duration("timeout_per_hop", time.Millisecond*200, "timeout per hop")
	root.PersistentFlags().Int("start_ttl", 1, "start ttl")
}

func run(cmd *cobra.Command, args []string) {
	source, _ := root.PersistentFlags().GetString("source")
	target, _ := root.PersistentFlags().GetString("target")
	sPort, _ := root.PersistentFlags().GetUint16("source_port")
	dPort, _ := root.PersistentFlags().GetUint16("target_port")
	retry, _ := root.PersistentFlags().GetInt("retry")
	maxUnreply, _ := root.PersistentFlags().GetInt("max_unreply")
	tp, _ := root.PersistentFlags().GetString("type")
	to, _ := root.PersistentFlags().GetDuration("timeout_per_hop")
	ttlStart, _ := root.PersistentFlags().GetInt("start_ttl")
	conf := go_mtr.Config{
		MaxUnReply:  maxUnreply,
		NextHopWait: to,
	}
	if tp == "icmp" {
		conf.ICMP = true
	}
	if tp == "udp" {
		conf.UDP = true
	}
	tracer, err := go_mtr.NewTrace(conf)
	if err != nil {
		fmt.Printf("init trace error (%v)\n", err)
		return
	}
	t, err := go_mtr.GetTrace(&go_mtr.Trace{
		SrcAddr: source,
		DstAddr: target,
		SrcPort: sPort,
		DstPort: dPort,
		Retry:   retry,
	})
	if err != nil {
		fmt.Printf("trace param error (%v)", err)
		return
	}
	res := tracer.BatchTrace([]go_mtr.Trace{*t}, uint8(ttlStart))
	for _, r := range res {
		fmt.Println("================not aggregate==============")
		fmt.Println(r.Marshal())
		fmt.Println("==================aggregate================")
		fmt.Println(r.MarshalAggregate())
	}
}

func main() {
	err := root.Execute()
	if err != nil {
		panic(err)
	}
}
