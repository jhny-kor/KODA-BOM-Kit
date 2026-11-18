package hardware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"time"

	"koda.local/security-sbom-linux/internal/model"
)

// Vendor fill-in values shared by unrelated machines. Hashing them would make
// different servers look like one asset, so they are treated as absent.
var identityPlaceholders = map[string]bool{
	"none": true, "n/a": true, "na": true, "unknown": true, "invalid": true, "default string": true,
	"not specified": true, "not applicable": true, "not available": true, "not present": true,
	"to be filled by o.e.m.": true, "o.e.m.": true, "oem": true, "system serial number": true,
	"chassis serial number": true, "base board serial number": true, "serial": true, "0123456789": true,
	"uninitialized": true,
}

func identityDigest(value string, lower bool) string {
	value = strings.TrimSpace(value)
	if lower {
		value = strings.ToLower(value)
	}
	compact := strings.NewReplacer("-", "", " ", "", ":", "", ".", "").Replace(strings.ToLower(value))
	// All-zero UUIDs and "FFFF..." serials are placeholders too.
	if compact == "" || identityPlaceholders[strings.ToLower(value)] || strings.Count(compact, compact[:1]) == len(compact) {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// HostIdentity returns digests of the machine-id and DMI identifiers below root.
// DMI serials are usually readable only by root; an unreadable value is reported
// as an issue and left empty rather than guessed.
func HostIdentity(ctx context.Context, root string) (model.HostIdentity, []model.Issue) {
	r, err := os.OpenRoot(root)
	if err != nil {
		return model.HostIdentity{}, []model.Issue{{Collector: "host-identity", Status: "failed", Message: "host identity root unavailable"}}
	}
	defer r.Close()
	c := collector{ctx: ctx, root: r, now: time.Now().UTC().Format(time.RFC3339)}
	c.detectScope()
	id := model.HostIdentity{ObservationScope: c.scope}
	for _, p := range []string{"etc/machine-id", "var/lib/dbus/machine-id"} {
		if v := c.read(p); len(v) == 32 && strings.Trim(strings.ToLower(v), "0123456789abcdef") == "" {
			id.MachineIDSHA256 = identityDigest(v, true)
			break
		}
	}
	id.ProductUUIDSHA256 = identityDigest(c.read("sys/class/dmi/id/product_uuid"), true)
	id.ProductSerialSHA256 = identityDigest(c.read("sys/class/dmi/id/product_serial"), false)
	id.BoardSerialSHA256 = identityDigest(c.read("sys/class/dmi/id/board_serial"), false)
	for i := range c.issues {
		c.issues[i].Collector = "host-identity"
	}
	if id.MachineIDSHA256 == "" && id.ProductUUIDSHA256 == "" && id.ProductSerialSHA256 == "" && id.BoardSerialSHA256 == "" {
		c.issues = append(c.issues, model.Issue{Collector: "host-identity", Status: "not_observed", Message: "no usable machine-id or DMI identifier; use --asset-tag to label this host"})
	}
	return id, c.issues
}
