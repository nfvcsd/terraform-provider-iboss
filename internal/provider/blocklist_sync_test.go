package provider_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6/tf6server"

	"github.com/nfvcsd/iboss-terraform/internal/client"
	"github.com/nfvcsd/iboss-terraform/internal/provider"
	"github.com/nfvcsd/iboss-terraform/internal/testutil"
)

// cliHarness runs the real Terraform (or OpenTofu) CLI against an in-process
// provider wired to the simulator. Unlike terraform-plugin-testing, it
// supports for_each, import blocks with for_each, and external scripts.
type cliHarness struct {
	t         *testing.T
	terraform string
	env       []string
}

func newCLIHarness(t *testing.T, sim *testutil.Simulator) *cliHarness {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("simulated acceptance test; set TF_ACC=1")
	}
	tf := os.Getenv("TF_ACC_TERRAFORM_PATH")
	if tf == "" {
		var err error
		if tf, err = exec.LookPath("terraform"); err != nil {
			t.Fatal("TF_ACC_TERRAFORM_PATH is unset and terraform is not on PATH")
		}
	}
	host := os.Getenv("TF_ACC_PROVIDER_HOST")
	if host == "" {
		host = "registry.terraform.io"
	}
	addr := host + "/nfvcsd/iboss"

	ctx, cancel := context.WithCancel(context.Background())
	reattachCh := make(chan *plugin.ReattachConfig, 1)
	closeCh := make(chan struct{})
	p := provider.New("test", provider.WithClientConfig(sim.ConfigureClient))()
	go func() {
		err := tf6server.Serve(addr, providerserver.NewProtocol6(p),
			tf6server.WithDebug(ctx, reattachCh, closeCh),
			tf6server.WithGoPluginLogger(hclog.NewNullLogger()),
			tf6server.WithLoggingSink(t))
		if err != nil {
			t.Errorf("provider server: %v", err)
		}
	}()
	var cfg *plugin.ReattachConfig
	select {
	case cfg = <-reattachCh:
	case <-time.After(30 * time.Second):
		cancel()
		t.Fatal("provider server did not start")
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-closeCh:
		case <-time.After(10 * time.Second):
		}
	})
	reattach, err := json.Marshal(map[string]any{addr: map[string]any{
		"Protocol": string(cfg.Protocol), "ProtocolVersion": cfg.ProtocolVersion, "Pid": cfg.Pid, "Test": cfg.Test,
		"Addr": map[string]string{"Network": cfg.Addr.Network(), "String": cfg.Addr.String()},
	}})
	if err != nil {
		t.Fatal(err)
	}
	// The child CLI gets no IBOSS_* credentials: the provider runs in this
	// test process and reads them from here.
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "IBOSS_") && !strings.HasPrefix(kv, "TF_") {
			env = append(env, kv)
		}
	}
	rc := filepath.Join(t.TempDir(), "empty.tfrc")
	if err := os.WriteFile(rc, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	env = append(env, "TF_REATTACH_PROVIDERS="+string(reattach), "TF_IN_AUTOMATION=1", "CHECKPOINT_DISABLE=1",
		"TF_CLI_CONFIG_FILE="+rc)
	return &cliHarness{t: t, terraform: tf, env: env}
}

// run executes name with args in dir; it returns stdout and the exit code.
func (h *cliHarness) run(dir, name string, args ...string) (string, int) {
	h.t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = h.env
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	code := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	} else if err != nil {
		h.t.Fatalf("%s %v: %v", name, args, err)
	}
	if code != 0 && code != 2 {
		h.t.Fatalf("%s %v exited %d:\n%s%s", name, args, code, out.String(), errOut.String())
	}
	return out.String(), code
}

func (h *cliHarness) tf(dir string, args ...string) (string, int) {
	h.t.Helper()
	return h.run(dir, h.terraform, args...)
}

// copyDir copies the example template so the test exercises the shipped files.
func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

type planJSON struct {
	ResourceChanges []struct {
		Address string `json:"address"`
		Change  struct {
			Actions   []string        `json:"actions"`
			Importing json.RawMessage `json:"importing"`
		} `json:"change"`
	} `json:"resource_changes"`
}

func TestAccBlocklistSyncWorkflow(t *testing.T) {
	sim := newAcc(t)
	t.Setenv(provider.EnvAPIKey, testutil.SimAPIKey)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required for the sync script")
	}

	sim.Groups = []map[string]any{
		{"groupNumber": 10, "groupName": "NFVMBL_ValElem"},
		{"groupNumber": 20, "groupName": "NFVMBL_Staff"},
		{"groupNumber": 32, "groupName": "NFVMBL_HS"},
		{"groupNumber": 34, "groupName": "NFtimed"},
		{"groupNumber": 47, "groupName": "NF/only:sites"},
	}
	sim.SetEntries(client.Blocklist, 32,
		map[string]any{"url": "weather.com/", "weight": 502},
		map[string]any{"url": `.*\.games\.example$`, "isRegex": 1, "direction": 2, "note": `quoted "note" ünïcode`},
		map[string]any{"url": "social.example"},
	)
	sim.SetEntries(client.Blocklist, 34,
		map[string]any{"url": "temp.example", "isTimedUrl": 1, "timedUrlExpiresInMinutes": 30},
		map[string]any{"url": "keep.example"},
	)
	sim.SetEntries(client.Blocklist, 47, map[string]any{"url": "only.example"})

	h := newCLIHarness(t, sim)
	_, thisFile, _, _ := runtime.Caller(0)
	repo := filepath.Join(filepath.Dir(thisFile), "..", "..")
	work := t.TempDir()
	copyDir(t, filepath.Join(repo, "examples", "blocklist-sync"), work)
	dir := filepath.Join(work, "Gateway", "Block List")
	sync := func() string {
		out, _ := h.run(work, python, "scripts/sync_blocklists.py", "--terraform", h.terraform, "--force")
		return out
	}
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	// 1. Export: one file per group, named like the console's group menu.
	t.Log(sync())
	var names []string
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".yaml") {
			names = append(names, e.Name())
		}
	}
	want := []string{"10. NFVMBL_ValElem.yaml", "20. NFVMBL_Staff.yaml", "32. NFVMBL_HS.yaml", "34. NFtimed.yaml", "47. NF_only_sites.yaml"}
	if strings.Join(names, "|") != strings.Join(want, "|") {
		t.Fatalf("files = %q, want %q", names, want)
	}
	hs := read("32. NFVMBL_HS.yaml")
	for _, s := range []string{`url: ".*\\.games\\.example$"`, "is_regex: true", "direction: 2", "weight: 502", `note: "quoted \"note\" ünïcode"`} {
		if !strings.Contains(hs, s) {
			t.Errorf("32. NFVMBL_HS.yaml missing %q:\n%s", s, hs)
		}
	}
	if timed := read("34. NFtimed.yaml"); !strings.Contains(timed, "timed_entries_not_managed:\n  - \"temp.example\"") ||
		strings.Contains(timed, "url: \"temp.example\"") {
		t.Errorf("timed entry handling:\n%s", timed)
	}
	if puts := sim.CountRequests(http.MethodPut, "/json/controls/blockList"); puts != 0 {
		t.Fatalf("export changed iboss: %d PUTs", puts)
	}

	// 2. Adopt: the first plan only imports existing entries.
	h.tf(work, "init", "-input=false", "-no-color")
	h.tf(work, "plan", "-input=false", "-no-color", "-out=tfplan")
	planOut, _ := h.tf(work, "show", "-json", "tfplan")
	var plan planJSON
	if err := json.Unmarshal([]byte(planOut), &plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.ResourceChanges) != 5 {
		t.Fatalf("resource changes = %d, want 5 (all non-timed entries)", len(plan.ResourceChanges))
	}
	for _, rc := range plan.ResourceChanges {
		if strings.Join(rc.Change.Actions, ",") != "no-op" || len(rc.Change.Importing) == 0 {
			t.Errorf("%s: actions %v importing %s; want an import with no changes", rc.Address, rc.Change.Actions, rc.Change.Importing)
		}
	}
	h.tf(work, "apply", "-input=false", "-no-color", "tfplan")
	if _, code := h.tf(work, "plan", "-input=false", "-no-color", "-detailed-exitcode"); code != 0 {
		t.Fatal("plan after adoption is not empty")
	}

	// 3. Manage: add an entry to an empty group's file and remove one from another.
	staff := filepath.Join(dir, "20. NFVMBL_Staff.yaml")
	b, _ := os.ReadFile(staff)
	if err := os.WriteFile(staff, bytes.Replace(b, []byte("entries: []"), []byte("entries:\n  - url: \"new.example\"\n    note: \"added in git\""), 1), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "32. NFVMBL_HS.yaml"), []byte(strings.Replace(hs, "  - url: \"social.example\"\n", "", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	h.tf(work, "apply", "-input=false", "-no-color", "-auto-approve")
	got := map[string]bool{}
	for _, e := range sim.Entries(client.Blocklist, 20) {
		got[e["url"].(string)+"|"+e["note"].(string)] = true
	}
	if !got["new.example|added in git"] {
		t.Errorf("group 20 entries = %v", sim.Entries(client.Blocklist, 20))
	}
	for _, e := range sim.Entries(client.Blocklist, 32) {
		if e["url"] == "social.example" {
			t.Error("social.example should have been deleted")
		}
	}
	if _, code := h.tf(work, "plan", "-input=false", "-no-color", "-detailed-exitcode"); code != 0 {
		t.Fatal("plan after changes is not empty")
	}

	// 4. Re-sync is stable, and a renamed group only renames its file.
	sync()
	if out := sync(); !strings.Contains(out, "5 unchanged, 0 added, 0 updated, 0 removed") {
		t.Errorf("second sync was not a no-op:\n%s", out)
	}
	if !sim.RenameGroup(32, "NFVMBL_HS_2026") {
		t.Fatal("group 32 missing from simulator")
	}
	if out := sync(); !strings.Contains(out, "added    Gateway/Block List/32. NFVMBL_HS_2026.yaml") ||
		!strings.Contains(out, "removed  Gateway/Block List/32. NFVMBL_HS.yaml") {
		t.Errorf("rename sync output:\n%s", out)
	}
	if _, code := h.tf(work, "plan", "-input=false", "-no-color", "-detailed-exitcode"); code != 0 {
		t.Fatal("renaming a group must not change managed entries")
	}
	if n := sim.CountRequests(http.MethodPut, "/json/controls/blockList"); n != 1 {
		t.Errorf("PUT requests = %d, want 1 (only new.example)", n)
	}
}
