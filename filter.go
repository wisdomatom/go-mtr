package go_mtr

import (
	"fmt"
)

func (t *tracer) ipv4Filter(pkg []byte) bool {
	if len(pkg) < 28 {
		return false
	}
	var src, dst string
	var ok bool
	controlMsgProto := pkg[20]
	switch controlMsgProto {
	case 11:
		src = fmt.Sprintf("%v.%v.%v.%v", pkg[20+20], pkg[20+21], pkg[20+22], pkg[20+23])
		dst = fmt.Sprintf("%v.%v.%v.%v", pkg[20+24], pkg[20+25], pkg[20+26], pkg[20+27])
	case 3:
		dst = fmt.Sprintf("%v.%v.%v.%v", pkg[12], pkg[13], pkg[14], pkg[15])
		src = fmt.Sprintf("%v.%v.%v.%v", pkg[16], pkg[17], pkg[18], pkg[19])
	case 0:
		dst = fmt.Sprintf("%v.%v.%v.%v", pkg[12], pkg[13], pkg[14], pkg[15])
		src = fmt.Sprintf("%v.%v.%v.%v", pkg[16], pkg[17], pkg[18], pkg[19])
	default:
		return false
	}
	_, ok = t.filterMap.Load(t.filterKey(src, dst))
	return ok
}
