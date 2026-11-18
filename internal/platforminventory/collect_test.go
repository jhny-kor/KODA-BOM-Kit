package platforminventory

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMacPrivacyAndFirmware(t *testing.T) {
	a, e := parseMac([]byte(`{"SPHardwareDataType":[{"machine_name":"Mac","machine_model":"Mac1,1","boot_rom_version":"1.2","chip_type":"Apple Silicon","serial_number":"SECRET","platform_UUID":"SECRET"}],"SPSoftwareDataType":[{"os_version":"macOS 15 (24A)","user_name":"SECRET"}],"SPApplicationsDataType":[{"_name":"Editor","version":"3.2","path":"/Users/SECRET/Editor.app"}]}`))
	if e != nil || len(a) != 5 {
		t.Fatalf("%v %v", a, e)
	}
	b, _ := json.Marshal(a)
	if strings.Contains(string(b), "SECRET") {
		t.Fatal("private data retained")
	}
	if a[1].ParentID != a[0].ID {
		t.Fatal("firmware parent missing")
	}
}
func TestWindowsPrivacyAndVersions(t *testing.T) {
	a, e := parseWindows([]byte(`[{"kind":"firmware","name":"BIOS","identity":"bios","version":"1.2","serial":"SECRET"},{"kind":"operating-system","name":"Windows","identity":"windows","version":"10.0","build":"26100","username":"SECRET"}]`))
	if e != nil || len(a) != 2 || a[1].Properties["build"] != "26100" {
		t.Fatalf("%v %v", a, e)
	}
	b, _ := json.Marshal(a)
	if strings.Contains(string(b), "SECRET") {
		t.Fatal("private field retained")
	}
}
func TestBoundedOutput(t *testing.T) {
	var b boundedOutput
	if _, e := b.Write(make([]byte, maxOutput+1)); e == nil || b.Len() != 0 {
		t.Fatal("limit bypass")
	}
}
