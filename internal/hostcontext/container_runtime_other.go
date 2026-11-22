//go:build !linux

package hostcontext

import (
	"context"
	"koda.local/security-sbom-linux/internal/model"
)

func ContainerProcesses(context.Context, []int, string, string) ([]model.ProcessLink, []model.Issue) {
	return nil, []model.Issue{{Collector: "host-context", Status: "not_supported", Message: "container runtime observations require Linux"}}
}
