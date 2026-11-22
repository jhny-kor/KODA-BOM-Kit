//go:build linux

package hostcontext

import (
	"context"
	"io"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	"koda.local/security-sbom-linux/internal/model"
)

const maxSocketFDs = 1 << 18

// listeningSockets reads the network namespace that pid belongs to. When
// connections is not nil it also receives the namespace's outbound TCP connections.
func listeningSockets(root *os.Root, out *model.Context, pid int, connections map[uint64]model.Connection) map[uint64]model.Socket {
	sockets := map[uint64]model.Socket{}
	var established map[uint64]establishedSocket
	if connections != nil {
		established = map[uint64]establishedSocket{}
	}
	base := "proc/" + strconv.Itoa(pid) + "/net/"
	for _, protocol := range []string{"tcp", "tcp6", "udp", "udp6"} {
		f, err := openNoFollow(root, base+protocol)
		if os.IsNotExist(err) {
			continue // protocol family disabled
		}
		if err != nil {
			issue(out, statusFor(err), base+protocol, "socket table unavailable")
			continue
		}
		complete := parseSocketTable(protocol, io.LimitReader(f, 256<<20), sockets, established)
		f.Close()
		if !complete {
			issue(out, "incomplete", base+protocol, "listening socket limit reached")
			break
		}
	}
	if len(established) >= maxEstablished {
		issue(out, "incomplete", base+"tcp", "established connection limit reached; outbound relationships are incomplete")
	}
	if connections == nil {
		return sockets
	}
	// Peers at one of this namespace's own addresses are local, not off-host.
	local := map[string]bool{}
	if f, err := openNoFollow(root, base+"fib_trie"); err == nil {
		parseFibTrieLocal(io.LimitReader(f, 16<<20), local)
		f.Close()
	}
	if data, err := readBounded(root, base+"if_inet6"); err == nil {
		parseIfInet6(string(data), local)
	}
	rangeData, _ := readBounded(root, "proc/sys/net/ipv4/ip_local_port_range")
	for inode, c := range outbound(sockets, established, ephemeralRange(string(rangeData))) {
		if local[c.RemoteAddress] && c.RemoteScope != "loopback" {
			c.RemoteScope = "local-host"
		}
		connections[inode] = c
	}
	return sockets
}

// socketOwner maps each listening inode to the processes holding it.
type socketOwner struct {
	ctx     context.Context
	root    *os.Root
	out     *model.Context
	sockets map[uint64]model.Socket
	// Outbound connections in the namespace; nil when not collected.
	connections map[uint64]model.Connection
	owned       map[uint64]bool
	budget      int
	reported    bool
}

func (s *socketOwner) process(prefix string) ([]model.Socket, []model.Connection) {
	if len(s.sockets) == 0 && len(s.connections) == 0 || s.budget <= 0 || s.ctx.Err() != nil {
		return nil, nil
	}
	dir, err := s.root.Open(prefix + "/fd")
	if err != nil {
		if os.IsPermission(err) && !s.reported {
			s.reported = true
			issue(s.out, "permission_denied", prefix+"/fd", "process descriptors unreadable; some listening sockets remain unattributed")
		}
		return nil, nil
	}
	names, err := dir.Readdirnames(s.budget + 1)
	dir.Close()
	if err != nil && err != io.EOF {
		return nil, nil
	}
	if len(names) > s.budget {
		names = names[:s.budget]
		issue(s.out, "incomplete", prefix+"/fd", "process descriptor limit reached")
	}
	s.budget -= len(names)
	seen := map[uint64]bool{}
	var found []model.Socket
	var connections []model.Connection
	for _, name := range names {
		target, err := s.root.Readlink(prefix + "/fd/" + name)
		if err != nil {
			continue
		}
		inode, ok := socketInode(target)
		if !ok || seen[inode] {
			continue
		}
		if socket, listening := s.sockets[inode]; listening {
			seen[inode] = true
			s.owned[inode] = true
			found = append(found, socket)
		} else if c, ok := s.connections[inode]; ok {
			seen[inode] = true
			connections = append(connections, c)
		}
	}
	sortSockets(found)
	return found, aggregateConnections(connections)
}

func (s *socketOwner) unattributed() []model.Socket {
	var rest []model.Socket
	for inode, socket := range s.sockets {
		if !s.owned[inode] {
			rest = append(rest, socket)
		}
	}
	sortSockets(rest)
	return rest
}

// NamespaceSockets reads the listening sockets in the network namespace of
// pids[0] and groups them by the executable of the listed processes that hold
// them. Executable paths are relative to the processes' own root, so a
// container's paths match its root filesystem. Sockets held only by other
// processes (for example sibling containers in a pod) are left out.
func NamespaceSockets(ctx context.Context, pids []int) (map[string][]model.Socket, []model.Issue) {
	out := &model.Context{}
	if len(pids) == 0 {
		return nil, nil
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		return nil, nil
	}
	defer root.Close()
	// ponytail: container collections keep listening sockets only; outbound
	// connections are recorded for host processes.
	owners := socketOwner{ctx: ctx, root: root, out: out, sockets: listeningSockets(root, out, pids[0], nil), owned: map[uint64]bool{}, budget: maxSocketFDs}
	byExecutable := map[string][]model.Socket{}
	for _, pid := range pids {
		prefix := "proc/" + strconv.Itoa(pid)
		exe, err := root.Readlink(prefix + "/exe")
		if err != nil || strings.HasSuffix(exe, " (deleted)") {
			continue
		}
		if exe = safeRuntimePath(exe); exe == "" {
			continue
		}
		listening, _ := owners.process(prefix)
		for _, socket := range listening {
			if !slices.Contains(byExecutable[exe], socket) {
				byExecutable[exe] = append(byExecutable[exe], socket)
			}
		}
	}
	for exe := range byExecutable {
		sortSockets(byExecutable[exe])
	}
	return byExecutable, out.Issues
}

func sortSockets(list []model.Socket) {
	sort.Slice(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Address < b.Address
	})
}
