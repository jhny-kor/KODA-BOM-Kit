//go:build linux && (amd64 || arm64)

package hardware

import (
	"errors"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Layouts of include/uapi/linux/ipmi.h on 64-bit targets.
type ipmiSystemAddr struct {
	AddrType int32
	Channel  int16
	Lun      uint8
	_        uint8
}
type ipmiMsg struct {
	Netfn, Cmd uint8
	DataLen    uint16
	_          [4]byte
	Data       *byte
}
type ipmiReq struct {
	Addr    *byte
	AddrLen uint32
	_       [4]byte
	Msgid   int64
	Msg     ipmiMsg
}
type ipmiRecv struct {
	RecvType int32
	_        [4]byte
	Addr     *byte
	AddrLen  uint32
	_        [4]byte
	Msgid    int64
	Msg      ipmiMsg
}

func ioc(dir, nr, size uintptr) uintptr { return dir<<30 | size<<16 | uintptr('i')<<8 | nr }

var (
	ipmictlSendCommand     = ioc(2, 13, unsafe.Sizeof(ipmiReq{}))  // _IOR
	ipmictlReceiveMsgTrunc = ioc(3, 11, unsafe.Sizeof(ipmiRecv{})) // _IOWR
)

const (
	ipmiSystemInterfaceAddrType = 0x0c
	ipmiBMCChannel              = 0x0f
	ipmiResponseRecvType        = 1
)

// bmc asks the local BMC for its device ID through the kernel IPMI driver.
// Get Device ID is a read-only query; it does not change BMC state.
func (c *collector) bmc() {
	var fd int
	var source string
	err := errors.New("no IPMI device")
	for _, p := range []string{"/dev/ipmi0", "/dev/ipmi/0", "/dev/ipmidev/0"} {
		if fd, err = unix.Open(p, unix.O_RDWR|unix.O_CLOEXEC, 0); err == nil || !errors.Is(err, unix.ENOENT) {
			source = p
			break
		}
	}
	if err != nil {
		if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
			c.issue(source, "permission_denied", "IPMI device requires root; BMC firmware not read")
		} else if _, statErr := c.root.Stat("sys/firmware/dmi/entries/38-0"); statErr == nil {
			c.issue("sys/firmware/dmi/entries/38-0", "not_observed", "SMBIOS reports a BMC but no IPMI device interface is available (ipmi_si and ipmi_devintf modules); BMC firmware not read")
		}
		return
	}
	defer unix.Close(fd)
	resp, err := ipmiGetDeviceID(fd)
	if err != nil {
		c.issue(source, "incomplete", "BMC did not answer Get Device ID; BMC firmware not read")
		return
	}
	if id, ok := parseDeviceID(resp); ok {
		c.addBMC(source, id)
	} else {
		c.issue(source, "incomplete", "BMC Get Device ID response unusable")
	}
}

func ipmiGetDeviceID(fd int) ([]byte, error) {
	addr := &ipmiSystemAddr{AddrType: ipmiSystemInterfaceAddrType, Channel: ipmiBMCChannel}
	req := &ipmiReq{Addr: (*byte)(unsafe.Pointer(addr)), AddrLen: uint32(unsafe.Sizeof(*addr)), Msgid: 1, Msg: ipmiMsg{Netfn: 0x06, Cmd: 0x01}}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), ipmictlSendCommand, uintptr(unsafe.Pointer(req))); errno != 0 {
		return nil, errno
	}
	runtime.KeepAlive(addr)
	data := make([]byte, 64)
	from := make([]byte, 32)
	for range 3 { // skip unrelated events queued on this descriptor
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		if n, err := unix.Poll(fds, 5000); err != nil || n == 0 {
			return nil, os.ErrDeadlineExceeded
		}
		recv := &ipmiRecv{Addr: &from[0], AddrLen: uint32(len(from)), Msg: ipmiMsg{Data: &data[0], DataLen: uint16(len(data))}}
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), ipmictlReceiveMsgTrunc, uintptr(unsafe.Pointer(recv))); errno != 0 {
			return nil, errno
		}
		if recv.RecvType == ipmiResponseRecvType && recv.Msgid == 1 {
			return append([]byte(nil), data[:min(int(recv.Msg.DataLen), len(data))]...), nil
		}
	}
	return nil, errors.New("no Get Device ID response")
}
