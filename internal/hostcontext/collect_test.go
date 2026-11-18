package hostcontext

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, root, p, data string) {
	t.Helper()
	target := filepath.Join(root, p)
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}
func TestStaticAllowlistedConfigurationAndNoSecrets(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/php/8.2/php.ini", `; session.serialize_handler=php_serialize
session.upload_progress.enabled = On
session.serialize_handler = php_binary
session.save_path = "PASSWORD_SECRET"
smtp.password=MAIL_SECRET
`)
	write(t, root, "etc/httpd/conf.modules.d/00.conf", `# LoadModule secret_module SECRET
LoadModule http2_module modules/mod_http2.so
AuthUserFile /secret/PASSWORD_SECRET
`)
	write(t, root, "etc/nginx/nginx.conf", `http { server { location / { alias /secret/PASSWORD_SECRET; rewrite ^/foo /bar; proxy_set_header Authorization TOKEN_SECRET; } } }
`)
	write(t, root, "opt/tomcat/conf/server.xml", `<Server><Service><Connector protocol="AJP/1.3" port="8009" secret="TOKEN_SECRET"/><Connector protocol="HTTP/1.1"><UpgradeProtocol className="org.apache.coyote.http2.Http2Protocol"/></Connector></Service></Server>`)
	out := Collect(context.Background(), root, false)
	if out.Mode != "filesystem" || out.Status != "completed" {
		t.Fatalf("unexpected context: %+v", out)
	}
	if out.RunningKernel != "" || len(out.ProcessLinks) > 0 || len(out.LoadedModules) > 0 {
		t.Fatal("host runtime leaked into static target")
	}
	values := map[string]string{}
	for _, s := range out.Settings {
		if s.State != "declared" {
			t.Fatalf("static value not declared: %+v", s)
		}
		values[s.Name] = s.Value
		if strings.HasPrefix(s.Path, "/") {
			t.Fatal("absolute evidence path leaked")
		}
	}
	for name, want := range map[string]string{"session.upload_progress.enabled": "true", "session.serialize_handler": "php_binary", "LoadModule.http2_module": "true", "directive.alias": "true", "directive.rewrite": "true", "connector.ajp": "true", "upgrade.http2": "true"} {
		if values[name] != want {
			t.Fatalf("%s=%q, wanted %q", name, values[name], want)
		}
	}
	raw, _ := json.Marshal(out)
	for _, secret := range []string{"PASSWORD_SECRET", "MAIL_SECRET", "TOKEN_SECRET", "secret_module", "8009"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("secret/raw config %q in output", secret)
		}
	}
}
func TestSymlinkEscapeIsNotRead(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	write(t, outside, "php.ini", "session.serialize_handler=php_binary\n")
	if err := os.MkdirAll(filepath.Join(root, "etc/php"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "php.ini"), filepath.Join(root, "etc/php/php.ini")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "opt")); err != nil {
		t.Fatal(err)
	}
	out := Collect(context.Background(), root, false)
	if len(out.Settings) != 0 {
		t.Fatalf("symlink content read: %+v", out)
	}
}
func TestVirtualAndContainerTreesExcluded(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{"proc/php.ini", "sys/php.ini", "dev/php.ini", "run/php.ini", "var/lib/docker/php.ini", "var/lib/containerd/php.ini", "var/lib/containers/php.ini"} {
		write(t, root, p, "session.upload_progress.enabled=1")
	}
	out := Collect(context.Background(), root, false)
	if len(out.Settings) != 0 {
		t.Fatalf("excluded data read: %+v", out.Settings)
	}
}
func TestInvalidConfigurationIsUnknownNotLeaked(t *testing.T) {
	root := t.TempDir()
	write(t, root, "php.ini", "session.serialize_handler=SECRET\nsession.upload_progress.enabled=SECRET\n")
	out := Collect(context.Background(), root, false)
	if len(out.Settings) != 2 {
		t.Fatal(out)
	}
	for _, s := range out.Settings {
		if s.Value != "unknown" {
			t.Fatalf("unexpected config data %+v", s)
		}
	}
}
func TestBrokenXMLIsPartial(t *testing.T) {
	root := t.TempDir()
	write(t, root, "conf/server.xml", "<Server><Connector secret=\"DO_NOT_LEAK\">")
	out := Collect(context.Background(), root, false)
	if out.Status != "partial" || len(out.Issues) != 1 {
		t.Fatalf("unexpected context: %+v", out)
	}
	if len(out.Settings) > 0 {
		t.Fatal("partial malformed XML presented as evidence")
	}
}
func TestOversizedFileIsPartialAndBounded(t *testing.T) {
	root := t.TempDir()
	write(t, root, "php.ini", strings.Repeat("x", maxFileBytes+1))
	out := Collect(context.Background(), root, false)
	if out.Status != "partial" || len(out.Settings) > 0 {
		t.Fatalf("unexpected context: %+v", out)
	}
}
func TestCancelledContextIsPartial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out := Collect(ctx, t.TempDir(), false)
	if out.Status != "partial" || len(out.Settings) != 0 {
		t.Fatalf("unexpected context: %+v", out)
	}
}
func TestExcludedMountTypes(t *testing.T) {
	data := "1 0 8:1 / / rw - ext4 /dev/root rw\n2 1 0:3 / /srv/share rw - nfs4 server:/share rw\n3 1 0:4 / /mnt/name\\040with\\040space rw - fuse.sshfs user@host:/ rw\n"
	denied := excludedMounts(data)
	if !blocked("srv/share/php.ini", denied) || !blocked("mnt/name with space/php.ini", denied) || blocked("etc/php.ini", denied) {
		t.Fatalf("bad mount exclusion %+v", denied)
	}
}
func TestLiveRequestOnOfflineRootStaysStatic(t *testing.T) {
	root := t.TempDir()
	write(t, root, "proc/modules", "host_should_not_be_read 123 0 - Live 0\n")
	out := Collect(context.Background(), root, true)
	if out.Mode != "filesystem" || out.RunningKernel != "" || len(out.LoadedModules) > 0 {
		t.Fatalf("live data for offline root %+v", out)
	}
}

func TestExplicitPreflightPathsHonorCallerExclusions(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/php/php.ini", "session.upload_progress.enabled=1")
	write(t, root, "opt/ignored/php.ini", "session.serialize_handler=php_binary")
	out := CollectWithPaths(context.Background(), root, false, []string{"etc/php/php.ini"})
	if len(out.Settings) != 1 || out.Settings[0].Name != "session.upload_progress.enabled" {
		t.Fatalf("unexpected preflight subset %+v", out)
	}
	out = CollectWithPaths(context.Background(), root, false, nil)
	if len(out.Settings) != 0 {
		t.Fatalf("empty list scanned target %+v", out)
	}
	out = CollectWithPaths(context.Background(), root, false, []string{"../../etc/php.ini", "/etc/php.ini"})
	if len(out.Settings) != 0 {
		t.Fatalf("invalid preflight path accepted %+v", out)
	}
}

func TestSELinuxConfigIsDeclaredOnlyFromListedPaths(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/selinux"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/selinux/config"), []byte("SELINUX=enforcing\n"), 0644); err != nil {
		t.Fatal(err)
	}
	listed := CollectWithPaths(context.Background(), root, false, []string{"etc/selinux/config"})
	if len(listed.Settings) != 1 || listed.Settings[0].Value != "enforcing" || listed.Settings[0].State != "declared" {
		t.Fatalf("listed config: %+v", listed.Settings)
	}
	if excluded := CollectWithPaths(context.Background(), root, false, nil); len(excluded.Settings) != 0 {
		t.Fatalf("an excluded config must not be read: %+v", excluded.Settings)
	}
}

func TestSSHDGlobalSettingsFirstValueWins(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"etc/ssh/sshd_config":                 "# PermitRootLogin yes\nInclude /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin prohibit-password\npermitrootlogin yes\nLoginGraceTime=0\nMaxStartups 10:30:100\nPasswordAuthentication no\nMatch User backup\n  PasswordAuthentication yes\n",
		"etc/ssh/sshd_config.d/50-cloud.conf": "PasswordAuthentication yes\n",
		"etc/ssh/ssh_config":                  "PasswordAuthentication yes\n", // client config: ignored
	}
	var paths []string
	for p, v := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(v), 0644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	out := CollectWithPaths(context.Background(), root, false, paths)
	got := map[string]string{}
	for _, s := range out.Settings {
		got[s.Path+" "+s.Name] = s.Value
	}
	want := map[string]string{
		"etc/ssh/sshd_config sshd.PermitRootLogin":                        "prohibit-password",
		"etc/ssh/sshd_config sshd.LoginGraceTime":                         "0",
		"etc/ssh/sshd_config sshd.MaxStartups":                            "10:30:100",
		"etc/ssh/sshd_config sshd.PasswordAuthentication":                 "no",
		"etc/ssh/sshd_config.d/50-cloud.conf sshd.PasswordAuthentication": "yes",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}
