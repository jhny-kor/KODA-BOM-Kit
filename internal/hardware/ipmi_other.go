//go:build !linux || !(amd64 || arm64)

package hardware

func (c *collector) bmc() {}
