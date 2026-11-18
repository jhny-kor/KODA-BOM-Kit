package hardware

import "fmt"

// Vendor names for IANA enterprise numbers seen in BMC Get Device ID replies.
var ipmiManufacturers = map[uint32]string{
	11: "Hewlett Packard Enterprise", 343: "Intel", 674: "Dell", 2011: "Huawei",
	10876: "Supermicro", 19046: "Lenovo",
}

type bmcIdentity struct {
	props    map[string]string
	firmware string
	vendor   string
}

// parseDeviceID decodes an IPMI App "Get Device ID" response (IPMI 2.0
// section 20.1), including the leading completion code.
func parseDeviceID(resp []byte) (bmcIdentity, bool) {
	if len(resp) < 12 || resp[0] != 0 {
		return bmcIdentity{}, false
	}
	manufacturer := uint32(resp[7]) | uint32(resp[8])<<8 | uint32(resp[9]&0x0f)<<16
	id := bmcIdentity{
		// Major is binary (bits 6:0), minor is BCD, as ipmitool prints it.
		firmware: fmt.Sprintf("%d.%02x", resp[3]&0x7f, resp[4]),
		vendor:   ipmiManufacturers[manufacturer],
		props: map[string]string{
			"deviceId": fmt.Sprintf("0x%02x", resp[1]), "deviceRevision": fmt.Sprintf("%d", resp[2]&0x0f),
			"ipmiVersion":    fmt.Sprintf("%d.%d", resp[5]&0x0f, resp[5]>>4),
			"manufacturerId": fmt.Sprintf("%d", manufacturer),
			"productId":      fmt.Sprintf("0x%04x", uint16(resp[10])|uint16(resp[11])<<8),
		},
	}
	if len(resp) >= 16 {
		id.props["auxFirmwareRevision"] = fmt.Sprintf("%02x%02x%02x%02x", resp[12], resp[13], resp[14], resp[15])
	}
	return id, true
}

func (c *collector) addBMC(source string, id bmcIdentity) {
	device := c.asset("device", "BMC", source, "", map[string]string{})
	for k, v := range id.props {
		device.Properties[k] = v
	}
	device.Vendor, device.Model = id.vendor, id.props["productId"]
	firmware := c.asset("firmware", "BMC firmware", source+"#get-device-id", device.ID, map[string]string{
		"state": "reported-running", "versionFormat": "ipmi-device-id",
		"auxFirmwareRevision": id.props["auxFirmwareRevision"],
	})
	firmware.Version, firmware.Vendor = id.firmware, id.vendor
	c.assets = append(c.assets, device, firmware)
}
