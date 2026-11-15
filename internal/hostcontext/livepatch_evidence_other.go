//go:build !linux

package hostcontext

import "errors"

func livepatchHostIdentity() (livepatchIdentity, error) {
	return livepatchIdentity{}, errors.New("livepatch evidence capture and import require Linux")
}
