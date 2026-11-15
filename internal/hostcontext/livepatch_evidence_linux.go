//go:build linux

package hostcontext

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"regexp"
	"strings"
	"time"
)

var bootIDToken = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func livepatchHostIdentity() (livepatchIdentity, error) {
	kernel, err := kernelRelease()
	if err != nil || !livepatchKernelToken.MatchString(kernel) {
		return livepatchIdentity{}, errors.New("cannot bind livepatch evidence to running kernel")
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		return livepatchIdentity{}, errors.New("cannot open livepatch identity root")
	}
	defer root.Close()
	data, err := readBounded(root, "proc/sys/kernel/random/boot_id")
	bootID := strings.TrimSpace(string(data))
	if err != nil || !bootIDToken.MatchString(bootID) {
		return livepatchIdentity{}, errors.New("cannot bind livepatch evidence to boot identity")
	}
	hash := sha256.Sum256([]byte(strings.ToLower(bootID)))
	return livepatchIdentity{Kernel: kernel, BootIDHash: hex.EncodeToString(hash[:]), Now: time.Now().UTC()}, nil
}
