//go:build integration

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// These mirror terraform-vault's config/ssh_secret_backend/sshca.yaml and
// config/ssh_secret_backend_role/sshca/signhost.yaml so the tool is exercised
// against the same mount, role and constraints production serves.
const (
	itMount          = "sshca"
	itRole           = "signhost"
	itPolicy         = "sshsignhost"
	itAppRoleMount   = "approle"
	itAllowedDomains = "int.example.net,example.org"
	itMaxLeaseTTL    = "315360000s" // 87600h
	itPuppetTTL      = "87600h"
)

func itVaultAddr() string {
	for _, key := range []string{"SSHSIGNHOST_TEST_VAULT_ADDR", "VAULT_ADDR"} {
		if v := os.Getenv(key); v != "" {
			return strings.TrimRight(v, "/")
		}
	}
	return "http://127.0.0.1:8200"
}

func itVaultToken() string {
	if v := os.Getenv("VAULT_TOKEN"); v != "" {
		return v
	}
	return "root"
}

func itWaitForVault(t *testing.T) {
	t.Helper()

	deadline := time.Now().Add(90 * time.Second)
	url := itVaultAddr() + "/v1/sys/health?standbyok=true"
	var last error
	for time.Now().Before(deadline) {
		resp, err := http.Get(url) // #nosec G107
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
			last = fmt.Errorf("HTTP %d", resp.StatusCode)
		} else {
			last = err
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("vault at %s never became healthy: %v", itVaultAddr(), last)
}

func itVaultAPI(t *testing.T, method, path string, body any) map[string]any {
	t.Helper()

	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("encoding %s %s: %v", method, path, err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequest(method, itVaultAddr()+"/v1/"+path, reader)
	if err != nil {
		t.Fatalf("building %s %s: %v", method, path, err)
	}
	req.Header.Set("X-Vault-Token", itVaultToken())
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading %s %s: %v", method, path, err)
	}
	if resp.StatusCode >= 300 {
		t.Fatalf("%s %s returned HTTP %d: %s", method, path, resp.StatusCode, raw)
	}

	parsed := map[string]any{}
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &parsed); err != nil {
			t.Fatalf("decoding %s %s: %v (%s)", method, path, err, raw)
		}
	}
	return parsed
}

// itSetupVault provisions the ssh CA mount, the host role, the sign policy and
// the approle the tool authenticates with, then returns the role_id. Every call
// is idempotent-by-overwrite so the test can be re-run against a live dev server.
func itSetupVault(t *testing.T) string {
	t.Helper()

	itWaitForVault(t)

	mounts := itVaultAPI(t, http.MethodGet, "sys/mounts", nil)
	if _, ok := mounts[itMount+"/"]; !ok {
		itVaultAPI(t, http.MethodPost, "sys/mounts/"+itMount, map[string]any{
			"type":        "ssh",
			"description": "SSH CA Engine",
			"config":      map[string]any{"max_lease_ttl": itMaxLeaseTTL},
		})
		itVaultAPI(t, http.MethodPost, itMount+"/config/ca", map[string]any{
			"generate_signing_key": true,
			"key_type":             "ssh-rsa",
		})
	}

	itVaultAPI(t, http.MethodPost, itMount+"/roles/"+itRole, map[string]any{
		"key_type":                "ca",
		"algorithm_signer":        "rsa-sha2-256",
		"ttl":                     itMaxLeaseTTL,
		"max_ttl":                 itMaxLeaseTTL,
		"allow_host_certificates": true,
		"allow_user_certificates": false,
		"allowed_domains":         itAllowedDomains,
		"allow_subdomains":        true,
		"allow_bare_domains":      false,
	})

	// The production policy grants sshca/sign/host while the only role that
	// exists is signhost, which is why production 403s today. Here we grant the
	// path the tool actually requests, proving the tool is correct once the
	// policy is fixed.
	itVaultAPI(t, http.MethodPut, "sys/policies/acl/"+itPolicy, map[string]any{
		"policy": fmt.Sprintf("path %q {\n  capabilities = [\"create\", \"update\"]\n}\n", itMount+"/sign/"+itRole),
	})

	auths := itVaultAPI(t, http.MethodGet, "sys/auth", nil)
	if _, ok := auths[itAppRoleMount+"/"]; !ok {
		itVaultAPI(t, http.MethodPost, "sys/auth/"+itAppRoleMount, map[string]any{"type": "approle"})
	}

	// bind_secret_id: false matches production; Vault demands another constraint
	// alongside it, which production satisfies with token_bound_cidrs.
	itVaultAPI(t, http.MethodPost, "auth/"+itAppRoleMount+"/role/"+itPolicy, map[string]any{
		"bind_secret_id":    false,
		"token_bound_cidrs": []string{"0.0.0.0/0"},
		"token_policies":    []string{itPolicy},
		"token_ttl":         "60s",
		"token_max_ttl":     "120s",
	})

	roleIDResp := itVaultAPI(t, http.MethodGet, "auth/"+itAppRoleMount+"/role/"+itPolicy+"/role-id", nil)
	data, ok := roleIDResp["data"].(map[string]any)
	if !ok {
		t.Fatalf("role-id response carried no data: %v", roleIDResp)
	}
	roleID, ok := data["role_id"].(string)
	if !ok || roleID == "" {
		t.Fatalf("role-id response carried no role_id: %v", data)
	}
	return roleID
}

func itBuildBinary(t *testing.T, dir string) string {
	t.Helper()

	if path := os.Getenv("SSHSIGNHOST_BIN"); path != "" {
		return path
	}

	binary := filepath.Join(dir, "sshsignhost")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building binary: %v\n%s", err, out)
	}
	return binary
}

func itWriteConfig(t *testing.T, dir, roleID string) string {
	t.Helper()

	path := filepath.Join(dir, "config.yaml")
	// The dev listener is plain HTTP, so tls_skip_verify never comes into play;
	// the TLS path stays covered by the httptest suite in main_test.go.
	body := fmt.Sprintf(`vault:
  addr: %q
  auth_method: approle
  approle_path: %q
  mount_point: %q
  role_name: %q
  role_id: %q
  timeout: 30s
`, itVaultAddr(), itAppRoleMount, itMount, itRole, roleID)

	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	return path
}

func itHostPublicKey(t *testing.T) (string, ssh.PublicKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating host key: %v", err)
	}
	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("converting host key: %v", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), pub
}

// itRun invokes the built binary with exactly the argv profiles::ssh::sign
// builds through generate().
func itRun(t *testing.T, binary, config, principals, publicKey string) (string, string, error) {
	t.Helper()

	cmd := exec.Command(binary,
		"--config", config,
		"--valid_principals", principals,
		"--ttl", itPuppetTTL,
		"--public_key", publicKey,
		"--json",
	)
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func TestIntegrationSignsHostCertificate(t *testing.T) {
	roleID := itSetupVault(t)

	dir := t.TempDir()
	binary := itBuildBinary(t, dir)
	config := itWriteConfig(t, dir, roleID)
	publicKey, parsedPublicKey := itHostPublicKey(t)

	// allowed_domains + allow_subdomains accepts these; see
	// TestIntegrationRejectsPrincipalsOutsideAllowedDomains for the bare
	// hostname/IP principals the Puppet manifest also sends today.
	principals := "node1.int.example.net,node1.example.org"
	wantPrincipals := []string{"node1.example.org", "node1.int.example.net"}

	stdout, stderr, err := itRun(t, binary, config, principals, publicKey)
	if err != nil {
		t.Fatalf("signing failed: %v (stderr %q)", err, stderr)
	}
	if stderr != "" {
		// generate() splices stderr onto stdout, so anything here breaks parsejson().
		t.Fatalf("stderr = %q, want empty", stderr)
	}

	var out signedKeyOutput
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("stdout %q is not JSON: %v", stdout, err)
	}
	if out.SignedKey == "" {
		t.Fatal("signed_key is empty")
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(out.SignedKey))
	if err != nil {
		t.Fatalf("signed_key does not parse as an SSH key: %v", err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		t.Fatalf("signed_key is a %T, want *ssh.Certificate", pub)
	}
	if cert.CertType != ssh.HostCert {
		t.Fatalf("cert type = %d, want host (%d)", cert.CertType, ssh.HostCert)
	}
	// Vault returns the principals sorted, not in the order they were sent.
	gotPrincipals := slices.Clone(cert.ValidPrincipals)
	slices.Sort(gotPrincipals)
	if !slices.Equal(gotPrincipals, wantPrincipals) {
		t.Fatalf("principals = %v, want %v", gotPrincipals, wantPrincipals)
	}
	if !bytes.Equal(cert.Key.Marshal(), parsedPublicKey.Marshal()) {
		t.Fatal("certificate was issued over a different public key")
	}

	validity := time.Unix(int64(cert.ValidBefore), 0).Sub(time.Unix(int64(cert.ValidAfter), 0)) // #nosec G115
	wantTTL, err := time.ParseDuration(itPuppetTTL)
	if err != nil {
		t.Fatalf("parsing ttl: %v", err)
	}
	if delta := validity - wantTTL; delta < -2*time.Hour || delta > 2*time.Hour {
		t.Fatalf("validity = %s, want ~%s", validity, wantTTL)
	}
}

// The Puppet manifest sends the bare hostname and the primary IP alongside the
// FQDN. The production role sets allow_bare_domains: false, so Vault refuses
// them -- a real gap in the estate's config, pinned here so it is not mistaken
// for a bug in this tool.
func TestIntegrationRejectsPrincipalsOutsideAllowedDomains(t *testing.T) {
	roleID := itSetupVault(t)

	dir := t.TempDir()
	binary := itBuildBinary(t, dir)
	config := itWriteConfig(t, dir, roleID)
	publicKey, _ := itHostPublicKey(t)

	stdout, stderr, err := itRun(t, binary, config, "node1,node1.int.example.net,198.51.100.55", publicKey)
	if err == nil {
		t.Fatalf("signing unexpectedly succeeded: %q", stdout)
	}
	if stdout != "" {
		// A half-written JSON document would break the catalog compile.
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, itMount+"/sign/"+itRole) {
		t.Fatalf("stderr = %q, want the sign path named", stderr)
	}
}

// Without the policy granting sshca/sign/signhost the tool must fail loudly,
// which is exactly what production does today against sshca/sign/host.
func TestIntegrationDeniedSignPathFailsCleanly(t *testing.T) {
	itSetupVault(t)

	denied := itPolicy + "-denied"
	itVaultAPI(t, http.MethodPut, "sys/policies/acl/"+denied, map[string]any{
		"policy": fmt.Sprintf("path %q {\n  capabilities = [\"create\", \"update\"]\n}\n", itMount+"/sign/host"),
	})
	itVaultAPI(t, http.MethodPost, "auth/"+itAppRoleMount+"/role/"+denied, map[string]any{
		"bind_secret_id":    false,
		"token_bound_cidrs": []string{"0.0.0.0/0"},
		"token_policies":    []string{denied},
		"token_ttl":         "60s",
		"token_max_ttl":     "120s",
	})
	resp := itVaultAPI(t, http.MethodGet, "auth/"+itAppRoleMount+"/role/"+denied+"/role-id", nil)
	roleID, _ := resp["data"].(map[string]any)["role_id"].(string)
	if roleID == "" {
		t.Fatal("denied role carried no role_id")
	}

	dir := t.TempDir()
	binary := itBuildBinary(t, dir)
	config := itWriteConfig(t, dir, roleID)
	publicKey, _ := itHostPublicKey(t)

	stdout, stderr, err := itRun(t, binary, config, "node1.int.example.net", publicKey)
	if err == nil {
		t.Fatalf("signing unexpectedly succeeded: %q", stdout)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "403") {
		t.Fatalf("stderr = %q, want an HTTP 403 named", stderr)
	}
}
