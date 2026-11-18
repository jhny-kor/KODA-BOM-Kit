//go:build linux

package hostcontext

import (
	"context"
	"reflect"
	"testing"
)

func TestRuntimeParsersRetainOnlyAllowlistedPaths(t *testing.T) {
	modules := parseModules("tls 123 1 - Live 0x123\nsecret=SECRET 1 0 - Live 0\ntls 123 1 - Live 0\n")
	if !reflect.DeepEqual(modules, []string{"tls"}) {
		t.Fatal(modules)
	}
	maps := parseMaps("7f123-7f456 r-xp 0 00:00 0 /usr/lib64/libssl.so.3\n7f123-7f456 r-xp 0 00:00 0 /proc/secret.so\n7f123-7f456 rw-p 0 00:00 0 [heap]\n7f123-7f456 r-xp 0 00:00 0 /opt/app/file.txt\n", []string{"proc"})
	if !reflect.DeepEqual(maps, []string{"usr/lib64/libssl.so.3"}) {
		t.Fatal(maps)
	}
	hints := parseInstallHints("java\x00-Dpassword=SECRET\x00-Dcatalina.base=/opt/tomcat\x00-Dweblogic.RootDirectory=/srv/weblogic\x00TOKEN=SECRET\x00-Djeus.home=/proc/secret\x00", []string{"proc"})
	if !reflect.DeepEqual(hints, []string{"opt/tomcat", "srv/weblogic"}) {
		t.Fatal(hints)
	}
}

func TestLiveContextCollectsKernelWithoutStaticFileWalk(t *testing.T) {
	want, err := kernelRelease()
	if err != nil {
		t.Fatal(err)
	}
	out := CollectWithPaths(context.Background(), "/", true, nil)
	if out.Mode != "live-host" || out.RunningKernel != want {
		t.Fatalf("unexpected live context %+v", out)
	}
	for _, setting := range out.Settings {
		if setting.State == "declared" { // "observed" and "derived" come from the live kernel
			t.Fatal("static settings unexpectedly walked")
		}
	}
}
