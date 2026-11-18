//go:build !darwin && !windows

package platforminventory

import (
	"context"
	"errors"
	"koda.local/security-sbom-linux/internal/model"
)

func Collect(ctx context.Context) ([]model.Asset, []model.Issue, error) {
	return nil, nil, errors.New("platform-inventory supports macOS and Windows; use scan on Linux")
}
