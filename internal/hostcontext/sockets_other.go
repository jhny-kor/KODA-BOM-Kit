//go:build !linux

package hostcontext

import (
	"context"

	"koda.local/security-sbom-linux/internal/model"
)

func NamespaceSockets(context.Context, []int) (map[string][]model.Socket, []model.Issue) {
	return nil, nil
}
