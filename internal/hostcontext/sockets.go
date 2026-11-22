package hostcontext

import (
	"bufio"
	"encoding/hex"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"

	"koda.local/security-sbom-linux/internal/model"
)

const maxSockets = 4096

// maxEstablished bounds established TCP sockets read per namespace; busy
// servers can hold far more, so outbound relationships are then incomplete.
const maxEstablished = 16384

type establishedSocket struct {
	conn      model.Connection
	localPort int
}

// parseSocketTable reads one /proc/net/{tcp,tcp6,udp,udp6} table and adds
// listening TCP and unconnected bound UDP sockets keyed by socket inode.
// Tables are streamed rather than buffered. When established is not nil,
// established TCP sockets are added to it until maxEstablished; the caller
// separates inbound (accepted) from outbound by local listening port.
// It returns false when the listening socket limit was reached.
func parseSocketTable(protocol string, r io.Reader, out map[uint64]model.Socket, established map[uint64]establishedSocket) bool {
	scanner := bufio.NewScanner(r)
	listenState := "0A" // TCP_LISTEN
	if strings.HasPrefix(protocol, "udp") {
		listenState = "07" // TCP_CLOSE: UDP socket without a connected peer
	}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		if fields[3] == "01" && established != nil && strings.HasPrefix(protocol, "tcp") && len(established) < maxEstablished {
			if inode, c, ok := parseEstablished(fields); ok {
				established[inode] = c
			}
			continue
		}
		if fields[3] != listenState {
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

// parseEstablished decodes one TCP_ESTABLISHED table row.
func parseEstablished(fields []string) (uint64, establishedSocket, bool) {
	local, remote := strings.Split(fields[1], ":"), strings.Split(fields[2], ":")
	if len(local) != 2 || len(remote) != 2 {
		return 0, establishedSocket{}, false
	}
	address, ok := decodeProcAddress(remote[0])
	remotePort, errR := strconv.ParseUint(remote[1], 16, 16)
	localPort, errL := strconv.ParseUint(local[1], 16, 16)
	inode, errI := strconv.ParseUint(fields[9], 10, 64)
	if !ok || errR != nil || errL != nil || errI != nil || inode == 0 {
		return 0, establishedSocket{}, false
	}
	return inode, establishedSocket{conn: model.Connection{Protocol: "tcp", RemoteAddress: address.String(), RemotePort: int(remotePort), RemoteScope: remoteScope(address)}, localPort: int(localPort)}, true
}

func remoteScope(ip net.IP) string {
	switch {
	case ip.IsLoopback():
		return "loopback"
	case ip.IsPrivate():
		return "private"
	case ip.IsLinkLocalUnicast():
		return "link-local"
	}
	return "public"
}

// outbound keeps established sockets whose local port is not a listening TCP
// port; the rest were accepted by a local server. A socket from a fixed port to
// a peer's ephemeral port is also treated as accepted, which covers servers
// that closed their listener after accepting. ephemeral is the namespace's
// ip_local_port_range.
func outbound(listening map[uint64]model.Socket, established map[uint64]establishedSocket, ephemeral [2]int) map[uint64]model.Connection {
	ports := map[int]bool{}
	for _, s := range listening {
		if strings.HasPrefix(s.Protocol, "tcp") {
			ports[s.Port] = true
		}
	}
	out := map[uint64]model.Connection{}
	inRange := func(port int) bool { return port >= ephemeral[0] && port <= ephemeral[1] }
	for inode, e := range established {
		if ports[e.localPort] || (inRange(e.conn.RemotePort) && !inRange(e.localPort)) {
			continue
		}
		out[inode] = e.conn
	}
	return out
}

// aggregateConnections groups a process's sockets per remote endpoint.
func aggregateConnections(list []model.Connection) []model.Connection {
	index := map[model.Connection]int{}
	var out []model.Connection
	for _, c := range list {
		key := c
		key.Count = 0
		if i, ok := index[key]; ok {
			out[i].Count++
			continue
		}
		index[key] = len(out)
		c.Count = 1
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.RemoteAddress != b.RemoteAddress {
			return a.RemoteAddress < b.RemoteAddress
		}
		return a.RemotePort < b.RemotePort
	})
	return out
}

// ephemeralRange parses ip_local_port_range, falling back to the Linux default.
func ephemeralRange(data string) [2]int {
	f := strings.Fields(data)
	if len(f) == 2 {
		low, errL := strconv.Atoi(f[0])
		high, errH := strconv.Atoi(f[1])
		if errL == nil && errH == nil && 0 < low && low <= high && high <= 65535 {
			return [2]int{low, high}
		}
	}
	return [2]int{32768, 60999}
}

// parseFibTrieLocal adds the namespace's IPv4 addresses: /proc/net/fib_trie
// lists each as a "|-- ADDRESS" leaf followed by "/32 host LOCAL".
func parseFibTrieLocal(r io.Reader, out map[string]bool) {
	scanner := bufio.NewScanner(r)
	current := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if leaf, ok := strings.CutPrefix(line, "|-- "); ok {
			current = leaf
		} else if strings.HasPrefix(line, "/32 host LOCAL") {
			if ip := net.ParseIP(current); ip != nil {
				out[ip.String()] = true
			}
		}
	}
}

// parseIfInet6 adds the namespace's IPv6 addresses from /proc/net/if_inet6.
func parseIfInet6(data string, out map[string]bool) {
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || len(fields[0]) != 32 {
			continue
		}
		if b, err := hex.DecodeString(fields[0]); err == nil {
			out[net.IP(b).String()] = true
		}
	}
}
