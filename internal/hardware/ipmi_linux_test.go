//go:build linux && (amd64 || arm64)

package hardware

import (
	"testing"
	"unsafe"
)

// Sizes from include/uapi/linux/ipmi.h on LP64; a mismatch would make the
// kernel read the wrong fields.
func TestIPMIStructLayouts(t *testing.T) {
	if s := unsafe.Sizeof(ipmiSystemAddr{}); s != 8 {
		t.Errorf("ipmi_system_interface_addr size %d", s)
	}
	if s := unsafe.Sizeof(ipmiReq{}); s != 40 {
		t.Errorf("ipmi_req size %d", s)
	}
	if s := unsafe.Sizeof(ipmiRecv{}); s != 48 {
		t.Errorf("ipmi_recv size %d", s)
	}
	if o := unsafe.Offsetof(ipmiRecv{}.Msg); o != 32 {
		t.Errorf("ipmi_recv.msg offset %d", o)
	}
	if ipmictlSendCommand != 0x8028690d || ipmictlReceiveMsgTrunc != 0xc030690b {
		t.Errorf("ioctl numbers %#x %#x", ipmictlSendCommand, ipmictlReceiveMsgTrunc)
	}
}
