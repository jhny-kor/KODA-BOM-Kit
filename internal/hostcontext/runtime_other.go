//go:build !linux

package hostcontext

import (
	"context"
	"koda.local/security-sbom-linux/internal/model"
	"os"
)

func collectRuntime(_ context.Context, _ *os.Root, out *model.Context, _ []string) {
	issue(out, "not_supported", "", "live context requires Linux")
}
