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

func TestAccURLListSyncWorkflow(t *testing.T) {
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
	sim.SetEntries(client.Allowlist, 10, map[string]any{"url": "library.example.org", "note": "library"})
	sim.SetEntries(client.Allowlist, 32, map[string]any{"url": "learning.example.org", "applyKeywordAndSafeSearch": 1})
	sim.SetEntries(client.Allowlist, 34, map[string]any{"url": "temp-allow.example", "isTimedUrl": 1, "timedUrlExpiresInMinutes": 5})
	sim.SetEntries(client.Allowlist, 47,
		map[string]any{"url": "only-allowed.example"},
		map[string]any{"url": "second.example", "doDlpScan": 0},
	)

	h := newCLIHarness(t, sim)
	_, thisFile, _, _ := runtime.Caller(0)
	repo := filepath.Join(filepath.Dir(thisFile), "..", "..")
	work := t.TempDir()
	copyDir(t, filepath.Join(repo, "examples", "url-list-sync"), work)
	blockDir := filepath.Join(work, "Gateway", "Block List")
	allowDir := filepath.Join(work, "Gateway", "Allowlist")
	sync := func() string {
		out, _ := h.run(work, python, "scripts/sync_lists.py", "--terraform", h.terraform, "--force")
		return out
	}
	read := func(dir, name string) string {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	write := func(dir, name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	yamlNames := func(dir string) string {
		var names []string
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".yaml") {
				names = append(names, e.Name())
			}
		}
		return strings.Join(names, "|")
	}
	mutations := func() int {
		n := 0
		for _, p := range []string{"/json/controls/blockList", "/json/controls/allowList"} {
			n += sim.CountRequests(http.MethodPut, p) + sim.CountRequests(http.MethodDelete, p)
		}
		return n
	}

	// 1. Export: one file per group in each folder, named like the console's group menu.
	t.Log(sync())
	want := "10. NFVMBL_ValElem.yaml|20. NFVMBL_Staff.yaml|32. NFVMBL_HS.yaml|34. NFtimed.yaml|47. NF_only_sites.yaml"
	for _, dir := range []string{blockDir, allowDir} {
		if got := yamlNames(dir); got != want {
			t.Fatalf("%s files = %q, want %q", dir, got, want)
		}
	}
	hs := read(blockDir, "32. NFVMBL_HS.yaml")
	for _, s := range []string{`url: ".*\\.games\\.example$"`, "is_regex: true", "direction: 2", "weight: 502", `note: "quoted \"note\" ünïcode"`} {
		if !strings.Contains(hs, s) {
			t.Errorf("block list 32 missing %q:\n%s", s, hs)
		}
	}
	if a := read(allowDir, "32. NFVMBL_HS.yaml"); !strings.HasPrefix(a, "# iboss allowlist for security group 32") ||
		!strings.Contains(a, "  - url: \"learning.example.org\"\n    apply_keyword_and_safe_search: true\n") || strings.Contains(a, "scan") {
		t.Errorf("allowlist 32:\n%s", a)
	}
	for dir, timedURL := range map[string]string{blockDir: "temp.example", allowDir: "temp-allow.example"} {
		if f := read(dir, "34. NFtimed.yaml"); !strings.Contains(f, "timed_entries_not_managed:\n  - \""+timedURL+"\"") ||
			strings.Contains(f, "url: \""+timedURL+"\"") {
			t.Errorf("timed entry handling in %s:\n%s", dir, f)
		}
	}
	if n := mutations(); n != 0 {
		t.Fatalf("export changed iboss: %d mutations", n)
	}

	// 2. Adopt: the first plan only imports existing entries from both lists.
	h.tf(work, "init", "-input=false", "-no-color")
	h.tf(work, "plan", "-input=false", "-no-color", "-out=tfplan")
	planOut, _ := h.tf(work, "show", "-json", "tfplan")
	var plan planJSON
	if err := json.Unmarshal([]byte(planOut), &plan); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, rc := range plan.ResourceChanges {
		counts[strings.SplitN(rc.Address, "[", 2)[0]]++
		if strings.Join(rc.Change.Actions, ",") != "no-op" || len(rc.Change.Importing) == 0 {
			t.Errorf("%s: actions %v importing %s; want an import with no changes", rc.Address, rc.Change.Actions, rc.Change.Importing)
		}
	}
	if counts["iboss_blocklist_entry.this"] != 5 || counts["iboss_allowlist_entry.this"] != 4 || len(counts) != 2 {
		t.Fatalf("planned imports = %v, want 5 block list and 4 allowlist entries", counts)
	}
	h.tf(work, "apply", "-input=false", "-no-color", "tfplan")
	if _, code := h.tf(work, "plan", "-input=false", "-no-color", "-detailed-exitcode"); code != 0 {
		t.Fatal("plan after adoption is not empty")
	}

	// 3. Manage: add and remove entries in both lists.
	write(blockDir, "20. NFVMBL_Staff.yaml", strings.Replace(read(blockDir, "20. NFVMBL_Staff.yaml"), "entries: []",
		"entries:\n  - url: \"new.example\"\n    note: \"added in git\"", 1))
	write(blockDir, "32. NFVMBL_HS.yaml", strings.Replace(hs, "  - url: \"social.example\"\n", "", 1))
	write(allowDir, "20. NFVMBL_Staff.yaml", strings.Replace(read(allowDir, "20. NFVMBL_Staff.yaml"), "entries: []",
		"entries:\n  - url: \"staff-tools.example\"\n    note: \"staff\"", 1))
	write(allowDir, "47. NF_only_sites.yaml", strings.Replace(read(allowDir, "47. NF_only_sites.yaml"), "  - url: \"second.example\"\n", "", 1))
	h.tf(work, "apply", "-input=false", "-no-color", "-auto-approve")
	has := func(l client.URLList, group int64, url string) bool {
		for _, e := range sim.Entries(l, group) {
			if e["url"] == url {
				return true
			}
		}
		return false
	}
	if !has(client.Blocklist, 20, "new.example") || has(client.Blocklist, 32, "social.example") {
		t.Errorf("block list changes not applied: 20=%v 32=%v", sim.Entries(client.Blocklist, 20), sim.Entries(client.Blocklist, 32))
	}
	if !has(client.Allowlist, 20, "staff-tools.example") || has(client.Allowlist, 47, "second.example") || !has(client.Allowlist, 47, "only-allowed.example") {
		t.Errorf("allowlist changes not applied: 20=%v 47=%v", sim.Entries(client.Allowlist, 20), sim.Entries(client.Allowlist, 47))
	}
	if _, code := h.tf(work, "plan", "-input=false", "-no-color", "-detailed-exitcode"); code != 0 {
		t.Fatal("plan after changes is not empty")
	}

	// 4. Re-sync is stable, and a renamed group only renames its files.
	sync()
	if out := sync(); !strings.Contains(out, "Gateway/Block List: 5 unchanged, 0 added, 0 updated, 0 removed") ||
		!strings.Contains(out, "Gateway/Allowlist: 5 unchanged, 0 added, 0 updated, 0 removed") {
		t.Errorf("second sync was not a no-op:\n%s", out)
	}
	if !sim.RenameGroup(32, "NFVMBL_HS_2026") {
		t.Fatal("group 32 missing from simulator")
	}
	out := sync()
	for _, folder := range []string{"Gateway/Block List", "Gateway/Allowlist"} {
		if !strings.Contains(out, "added    "+folder+"/32. NFVMBL_HS_2026.yaml") || !strings.Contains(out, "removed  "+folder+"/32. NFVMBL_HS.yaml") {
			t.Errorf("rename sync output for %s:\n%s", folder, out)
		}
	}
	if _, code := h.tf(work, "plan", "-input=false", "-no-color", "-detailed-exitcode"); code != 0 {
		t.Fatal("renaming a group must not change managed entries")
	}
	if n := mutations(); n != 4 {
		t.Errorf("mutations = %d, want 4 (two adds, two deletes)", n)
	}
}
