//go:build !linux

package hardware

func (c *collector) ethtool() {}
