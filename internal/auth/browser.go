package auth

import (
	"fmt"
	neturl "net/url"
	"os/exec"
	"runtime"
	"strings"
)

// OpenBrowser opens url in the default browser without a shell: fixed program, the address as one
// argument. The address is printed as well, so a failure here is not fatal for the caller.
func OpenBrowser(url string) error {
	cmd, err := browserCommand(runtime.GOOS, url)
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }() // reap the opener so it does not linger as a zombie
	return nil
}

// browserCommand returns the opener for goos. Windows uses rundll32 rather than "cmd /c start",
// which would read & in the query as a command separator.
func browserCommand(goos, raw string) (*exec.Cmd, error) {
	u, err := neturl.Parse(raw)
	okAddr := err == nil && u.User == nil && u.Opaque == "" &&
		(u.Scheme == "https" && u.Hostname() != "" || u.Scheme == "http" && u.Hostname() == "127.0.0.1")
	if !okAddr || strings.ContainsFunc(raw, func(r rune) bool { return r <= 0x20 || r == 0x7f }) {
		return nil, fmt.Errorf("refusing to open this address in a browser")
	}
	url := u.String()
	var cmd *exec.Cmd
	switch goos {
	case "darwin":
		cmd = exec.Command("/usr/bin/open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	cmd.Stdout, cmd.Stderr = nil, nil
	return cmd, nil
}
