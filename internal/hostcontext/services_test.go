package hostcontext

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"koda.local/security-sbom-linux/internal/model"
)

func TestEnabledServices(t *testing.T) {
	dir := t.TempDir()
	write := func(p, v string) {
		t.Helper()
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(v), 0644); err != nil {
			t.Fatal(err)
		}
	}
	link := func(target, p string) {
		t.Helper()
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, full); err != nil {
			t.Fatal(err)
		}
	}
	write("usr/lib/systemd/system/nginx.service", "[Unit]\nDescription=x\n[Service]\nExecStartPre=/usr/sbin/nginx -t\nExecStart=/usr/sbin/nginx -g 'daemon off;'\n")
	write("etc/systemd/system/nginx.service.d/override.conf", "[Service]\nExecStart=\nExecStart=-/opt/nginx/sbin/nginx\n")
	link("/usr/lib/systemd/system/nginx.service", "etc/systemd/system/multi-user.target.wants/nginx.service")
	write("usr/lib/systemd/system/ssh.socket", "[Socket]\nListenStream=22\nListenStream=/run/ssh.sock\nListenStream=bad value\n")
	write("usr/lib/systemd/system/ssh.service", "[Service]\nExecStart=/usr/sbin/sshd -D\n")
	link("/usr/lib/systemd/system/ssh.socket", "etc/systemd/system/sockets.target.wants/ssh.socket")
	link("/dev/null", "etc/systemd/system/bad.service")
	link("/usr/lib/systemd/system/bad.service", "etc/systemd/system/multi-user.target.wants/bad.service")
	write("usr/lib/systemd/system/getty@.service", "[Service]\nExecStart=-/sbin/agetty -o '-p' %I\n")
	link("/usr/lib/systemd/system/getty@.service", "etc/systemd/system/getty.target.wants/getty@tty1.service")
	write("usr/lib/systemd/system/dbus-broker.service", "[Service]\nExecStart=/usr/bin/dbus-broker-launch\n")
	link("/usr/lib/systemd/system/dbus-broker.service", "etc/systemd/system/dbus.service")
	write("usr/lib/systemd/system/dbus.socket", "[Socket]\nListenStream=/run/dbus/system_bus_socket\n")
	link("../dbus.socket", "usr/lib/systemd/system/sockets.target.wants/dbus.socket")
	write("usr/lib/systemd/system/logrotate.timer", "[Timer]\nOnCalendar=daily\nAccuracySec=1h\nPersistent=true\n")
	write("usr/lib/systemd/system/logrotate.service", "[Service]\nType=oneshot\nExecStart=/usr/sbin/logrotate /etc/logrotate.conf\n")
	link("/usr/lib/systemd/system/logrotate.timer", "etc/systemd/system/timers.target.wants/logrotate.timer")
	write("sys/fs/cgroup/system.slice/nginx.service/cgroup.procs", "123\n")
	write("sys/fs/cgroup/system.slice/system-getty.slice/getty@tty1.service/cgroup.procs", "456\n")
	write("sys/fs/cgroup/system.slice/ssh.service/cgroup.procs", "")
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	var out model.Context
	collectServices(root, &out, true, nil)
	want := []model.Service{
		{Unit: "dbus.socket", UnitFile: "usr/lib/systemd/system/dbus.socket", WantedBy: []string{"sockets.target"}, Executable: "usr/bin/dbus-broker-launch", Activates: "dbus.service", Listen: []string{"ListenStream=/run/dbus/system_bus_socket"}, State: "stopped"},
		{Unit: "getty@tty1.service", UnitFile: "usr/lib/systemd/system/getty@.service", WantedBy: []string{"getty.target"}, Executable: "sbin/agetty", State: "running"},
		{Unit: "logrotate.timer", UnitFile: "usr/lib/systemd/system/logrotate.timer", WantedBy: []string{"timers.target"}, Executable: "usr/sbin/logrotate", Activates: "logrotate.service", Schedule: []string{"OnCalendar=daily"}, State: "stopped"},
		{Unit: "nginx.service", UnitFile: "usr/lib/systemd/system/nginx.service", WantedBy: []string{"multi-user.target"}, Executable: "opt/nginx/sbin/nginx", State: "running"},
		{Unit: "ssh.socket", UnitFile: "usr/lib/systemd/system/ssh.socket", WantedBy: []string{"sockets.target"}, Executable: "usr/sbin/sshd", Activates: "ssh.service", Listen: []string{"ListenStream=22", "ListenStream=/run/ssh.sock"}, State: "stopped"},
	}
	if !reflect.DeepEqual(out.EnabledServices, want) {
		t.Fatalf("got  %+v\nwant %+v", out.EnabledServices, want)
	}
	var static model.Context
	collectServices(root, &static, false, map[string]bool{"usr/lib/systemd/system/ssh.socket": true})
	for _, s := range static.EnabledServices {
		if s.State != "" {
			t.Fatalf("directory scans must not report runtime state: %+v", s)
		}
		if s.Unit == "nginx.service" && s.Executable != "" {
			t.Fatalf("unit files outside the scan plan must not be read: %+v", s)
		}
	}
}
