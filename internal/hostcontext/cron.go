package hostcontext

import (
	"bufio"
	"bytes"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"

	"koda.local/security-sbom-linux/internal/model"
)

const maxScheduledJobs = 2000

var cronKeyword = regexp.MustCompile(`^@[a-z]{4,10}$`)
var cronUser = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

var cronDirectories = map[string]string{"etc/cron.hourly": "@hourly", "etc/cron.daily": "@daily", "etc/cron.weekly": "@weekly", "etc/cron.monthly": "@monthly"}

// collectScheduledJobs reads system and user crontabs and cron directory
// scripts. Only the schedule, user and absolute program path are kept.
// allowed, when not nil, limits reads to the caller's scan plan.
func collectScheduledJobs(root *os.Root, out *model.Context, allowed map[string]bool) {
	c := cronReader{root: root, out: out, allowed: allowed}
	// Debian's cron and run-parts skip names outside [A-Za-z0-9_-], such as backup.sh.
	if _, err := root.Lstat("etc/debian_version"); err == nil {
		c.debian = true
	}
	c.crontab("etc/crontab", "", true)
	for _, name := range c.list("etc/cron.d") {
		c.crontab("etc/cron.d/"+name, "", true)
	}
	// Debian keeps user crontabs in crontabs/<user>; cronie in cron/<user>.
	for _, dir := range []string{"var/spool/cron/crontabs", "var/spool/cron"} {
		for _, user := range c.list(dir) {
			if !cronUser.MatchString(user) {
				continue
			}
			c.crontab(dir+"/"+user, user, false)
		}
	}
	dirs := make([]string, 0, len(cronDirectories))
	for dir := range cronDirectories {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	for _, dir := range dirs {
		for _, name := range c.list(dir) {
			p := dir + "/" + name
			if st, err := root.Lstat(p); err == nil && st.Mode().IsRegular() && st.Mode()&0111 != 0 && c.permitted(p) {
				c.add(model.ScheduledJob{Source: p, Schedule: cronDirectories[dir], User: "root", Executable: p})
			}
		}
	}
}

type cronReader struct {
	root    *os.Root
	out     *model.Context
	allowed map[string]bool
	limited bool
	debian  bool
}

var debianPartName = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func (c *cronReader) permitted(p string) bool { return c.allowed == nil || c.allowed[p] }

// list returns the regular file names cron would read in dir, skipping
// hidden, backup and package-manager leftover files.
func (c *cronReader) list(dir string) []string {
	f, err := openNoFollow(c.root, dir)
	if err != nil {
		if os.IsPermission(err) {
			issue(c.out, "permission_denied", dir, "cron directory unreadable; scheduled jobs are incomplete")
		}
		return nil
	}
	entries, _ := f.ReadDir(4096)
	f.Close()
	var names []string
	for _, e := range entries {
		n := e.Name()
		if !e.Type().IsRegular() || strings.HasPrefix(n, ".") || strings.HasSuffix(n, "~") || strings.Contains(n, ".rpm") || strings.Contains(n, ".dpkg-") {
			continue
		}
		if c.debian && dir != "var/spool/cron/crontabs" && !debianPartName.MatchString(n) {
			continue
		}
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func (c *cronReader) add(job model.ScheduledJob) {
	if len(c.out.ScheduledJobs) >= maxScheduledJobs {
		if !c.limited {
			c.limited = true
			issue(c.out, "incomplete", job.Source, "scheduled job limit reached")
		}
		return
	}
	c.out.ScheduledJobs = append(c.out.ScheduledJobs, job)
}

// crontab parses one crontab. System crontabs carry a user field after the schedule.
func (c *cronReader) crontab(p, user string, system bool) {
	if !c.permitted(p) {
		return
	}
	data, err := readBounded(c.root, p)
	if err != nil {
		if os.IsPermission(err) {
			issue(c.out, "permission_denied", p, "crontab unreadable")
		}
		return
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 65536)
	line := 0
	for scanner.Scan() {
		line++
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") || cronAssignment(fields[0]) {
			continue
		}
		var schedule string
		if strings.HasPrefix(fields[0], "@") {
			schedule, fields = fields[0], fields[1:]
		} else if len(fields) >= 5 {
			schedule, fields = strings.Join(fields[:5], " "), fields[5:]
		} else {
			continue
		}
		if !scheduleValue.MatchString(schedule) && !cronKeyword.MatchString(schedule) {
			continue
		}
		job := model.ScheduledJob{Source: p, Line: line, Schedule: schedule, User: user}
		if system {
			// A line missing its user field would otherwise put a command or
			// assignment (possibly a credential) into the user value.
			if len(fields) == 0 || !cronUser.MatchString(fields[0]) {
				continue
			}
			job.User, fields = fields[0], fields[1:]
		}
		if len(fields) == 0 {
			continue
		}
		if program := strings.Trim(fields[0], `"'`); strings.HasPrefix(program, "/") && safeExecutable.MatchString(program) {
			job.Executable = strings.TrimPrefix(path.Clean(program), "/")
		}
		c.add(job)
	}
}

// cronAssignment reports an environment line such as MAILTO=root or PATH=...
func cronAssignment(first string) bool {
	name, _, ok := strings.Cut(first, "=")
	return ok && name != "" && !strings.ContainsAny(name, "*/,-@")
}
