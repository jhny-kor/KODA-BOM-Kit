package hostcontext

import (
	"bufio"
	"encoding/hex"
	"io"
	"net"
	"strconv"
	"strings"

	"koda.local/security-sbom-linux/internal/model"
)

const maxSockets = 4096

// parseSocketTable reads one /proc/net/{tcp,tcp6,udp,udp6} table and adds
// listening TCP and unconnected bound UDP sockets keyed by socket inode.
// Established connections are skipped line by line, so busy tables are streamed
// rather than buffered. It returns false when the socket limit was reached.
func parseSocketTable(protocol string, r io.Reader, out map[uint64]model.Socket) bool {
	scanner := bufio.NewScanner(r)
	listenState := "0A" // TCP_LISTEN
	if strings.HasPrefix(protocol, "udp") {
		listenState = "07" // TCP_CLOSE: UDP socket without a connected peer
	}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 || fields[3] != listenState {
			continue
		}
		local, remote := strings.Split(fields[1], ":"), strings.Split(fields[2], ":")
		if len(local) != 2 || len(remote) != 2 || remote[1] != "0000" {
			continue
		}
		address, ok := decodeProcAddress(local[0])
		port, err := strconv.ParseUint(local[1], 16, 16)
		inode, inodeErr := strconv.ParseUint(fields[9], 10, 64)
		if !ok || err != nil || inodeErr != nil || inode == 0 {
			continue
		}
		if len(out) >= maxSockets {
			return false
		}
		out[inode] = model.Socket{Protocol: protocol, Address: address.String(), Port: int(port), BindScope: bindScope(address)}
	}
	return true
}

// ponytail: procfs prints each 32-bit address word in host byte order; both
// supported targets (amd64, arm64) are little-endian. Big-endian needs a switch.
func decodeProcAddress(value string) (net.IP, bool) {
	b, err := hex.DecodeString(value)
	if err != nil || (len(b) != net.IPv4len && len(b) != net.IPv6len) {
		return nil, false
	}
	for i := 0; i < len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	return net.IP(b), true
}

func bindScope(ip net.IP) string {
	switch {
	case ip.IsUnspecified():
		return "all-interfaces"
	case ip.IsLoopback():
		return "loopback"
	}
	return "address"
}

// socketInode extracts N from an fd link target "socket:[N]".
func socketInode(target string) (uint64, bool) {
	value, ok := strings.CutPrefix(target, "socket:[")
	if !ok {
		return 0, false
	}
	value, ok = strings.CutSuffix(value, "]")
	if !ok {
		return 0, false
	}
	inode, err := strconv.ParseUint(value, 10, 64)
	return inode, err == nil && inode != 0
}
