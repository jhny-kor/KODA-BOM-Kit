package hardware

import "testing"

func TestParseDeviceID(t *testing.T) {
	// Dell iDRAC-style reply: fw 7.10, IPMI 2.0, manufacturer 674, product 0x0100, aux firmware.
	resp := []byte{0x00, 0x20, 0x81, 0x07, 0x10, 0x02, 0xbf, 0xa2, 0x02, 0x00, 0x00, 0x01, 0x00, 0x1e, 0x00, 0x00}
	id, ok := parseDeviceID(resp)
	if !ok || id.firmware != "7.10" || id.vendor != "Dell" {
		t.Fatalf("got %+v", id)
	}
	for k, want := range map[string]string{"manufacturerId": "674", "productId": "0x0100", "ipmiVersion": "2.0", "deviceRevision": "1", "auxFirmwareRevision": "001e0000"} {
		if id.props[k] != want {
			t.Errorf("%s = %q, want %q", k, id.props[k], want)
		}
	}
	if _, ok := parseDeviceID(append([]byte{0xc1}, resp[1:]...)); ok {
		t.Error("non-zero completion code accepted")
	}
	if _, ok := parseDeviceID(resp[:11]); ok {
		t.Error("truncated reply accepted")
	}
	// Device-available bit (7) of the major revision is not part of the version.
	resp[3] = 0x82
	if id, _ := parseDeviceID(resp); id.firmware != "2.10" {
		t.Errorf("firmware %q", id.firmware)
	}
}
