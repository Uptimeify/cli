package auth

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"testing"
)

// helperEnv names the helper a child process of the test binary runs instead of the tests.
const helperEnv = "UPTIMEIFY_AUTH_TEST_HELPER"

// helpers run in a child process of the test binary, so tests can check behaviour between two
// processes (the sign-in lock, the refresh race). Test files register theirs in init.
var helpers = map[string]func() int{}

func TestMain(m *testing.M) {
	if name := os.Getenv(helperEnv); name != "" {
		h, ok := helpers[name]
		if !ok {
			fmt.Fprintf(os.Stderr, "unknown test helper %q\n", name)
			os.Exit(2)
		}
		os.Exit(h())
	}
	os.Exit(m.Run())
}

// startHelper starts the helper name in a child process with env added to the environment and
// returns the running command. Stdout and Stderr are *bytes.Buffer; read them only after
// cmd.Wait. A helper still running when the test ends is killed.
func startHelper(t *testing.T, name string, env ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(append(os.Environ(), helperEnv+"="+name), env...)
	cmd.Stdout = new(bytes.Buffer)
	cmd.Stderr = new(bytes.Buffer)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper %s: %v", name, err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	return cmd
}
