//go:build linux

package hostcontext

import (
	"context"
	"io"
	"os"
	"sort"
	"strconv"

	"koda.local/security-sbom-linux/internal/model"
)

const maxSocketFDs = 1 << 18

// listeningSockets reads the collector's own network namespace. Sockets that
// exist only in another namespace (for example a container) are not listed.
func listeningSockets(root *os.Root, out *model.Context) map[uint64]model.Socket {
	sockets := map[uint64]model.Socket{}
	base := "proc/" + strconv.Itoa(os.Getpid()) + "/net/"
	for _, protocol := range []string{"tcp", "tcp6", "udp", "udp6"} {
		f, err := openNoFollow(root, base+protocol)
		if os.IsNotExist(err) {
			continue // protocol family disabled
		}
		if err != nil {
			issue(out, statusFor(err), base+protocol, "socket table unavailable")
			continue
		}
		complete := parseSocketTable(protocol, io.LimitReader(f, 256<<20), sockets)
		f.Close()
		if !complete {
			issue(out, "incomplete", base+protocol, "listening socket limit reached")
			break
		}
	}
	return sockets
}

// socketOwner maps each listening inode to the processes holding it.
type socketOwner struct {
	ctx      context.Context
	root     *os.Root
	out      *model.Context
	sockets  map[uint64]model.Socket
	owned    map[uint64]bool
	budget   int
	reported bool
}

func (s *socketOwner) process(prefix string) []model.Socket {
	if len(s.sockets) == 0 || s.budget <= 0 || s.ctx.Err() != nil {
		return nil
	}
	dir, err := s.root.Open(prefix + "/fd")
	if err != nil {
		if os.IsPermission(err) && !s.reported {
			s.reported = true
			issue(s.out, "permission_denied", prefix+"/fd", "process descriptors unreadable; some listening sockets remain unattributed")
		}
		return nil
	}
	names, err := dir.Readdirnames(s.budget + 1)
	dir.Close()
	if err != nil && err != io.EOF {
		return nil
	}
	if len(names) > s.budget {
		names = names[:s.budget]
		issue(s.out, "incomplete", prefix+"/fd", "process descriptor limit reached")
	}
	s.budget -= len(names)
	seen := map[uint64]bool{}
	var found []model.Socket
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
		}
	}
	sortSockets(found)
	return found
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
