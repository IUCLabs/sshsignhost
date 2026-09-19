package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testSignedKey = "ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20"
	testPublicKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDexample"
	testToken     = "hvs.CAESIFAKE"
	subprocessEnv = "SSHSIGNHOST_TEST_SUBPROCESS"
)

func TestMain(m *testing.M) {
	if os.Getenv(subprocessEnv) == "1" {
		main()
		return
	}
	os.Exit(m.Run())
}

type capturedRequest struct {
	path   string
	token  string
	body   map[string]string
	called bool
}

type fakeVault struct {
	t          *testing.T
	server     *httptest.Server
	authStatus int
	signStatus int
	signBody   string
	delay      time.Duration
	login      capturedRequest
	sign       capturedRequest
}

func newFakeVault(t *testing.T) *fakeVault {
	t.Helper()

	vault := &fakeVault{
		t:          t,
		authStatus: http.StatusOK,
		signStatus: http.StatusOK,
		signBody:   fmt.Sprintf(`{"data":{"signed_key":%q}}`, testSignedKey),
	}
	vault.server = httptest.NewTLSServer(http.HandlerFunc(vault.handle))
	t.Cleanup(vault.server.Close)
	return vault
}

func (f *fakeVault) handle(w http.ResponseWriter, r *http.Request) {
	if f.delay > 0 {
		time.Sleep(f.delay)
	}

	raw, err := io.ReadAll(r.Body)
	if err != nil {
		f.t.Errorf("reading request body: %v", err)
		return
	}
	body := map[string]string{}
	if err := json.Unmarshal(raw, &body); err != nil {
		f.t.Errorf("decoding request body %q: %v", raw, err)
		return
	}

	captured := capturedRequest{path: r.URL.Path, token: r.Header.Get("X-Vault-Token"), body: body, called: true}

	switch {
	case strings.HasSuffix(r.URL.Path, "/login"):
		f.login = captured
		if f.authStatus != http.StatusOK {
			w.WriteHeader(f.authStatus)
			_, _ = fmt.Fprint(w, `{"errors":["permission denied"]}`)
			return
		}
		_, _ = fmt.Fprintf(w, `{"auth":{"client_token":%q}}`, testToken)
	default:
		f.sign = captured
		if f.signStatus != http.StatusOK {
			w.WriteHeader(f.signStatus)
			_, _ = fmt.Fprint(w, `{"errors":["1 error occurred:\n\t* permission denied\n\n"]}`)
			return
		}
		_, _ = fmt.Fprint(w, f.signBody)
	}
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	return path
}

func approleConfig(t *testing.T, addr string) string {
	t.Helper()

	return writeConfig(t, fmt.Sprintf(`vault:
  addr: '%s'
  role_id: 'role-id-value'
  approle_path: 'approle'
  mount_point: 'sshca'
  role_name: 'signhost'
output_path: '/etc/ssh/ssh_host_rsa_key-cert.pem'
`, addr))
}

func kubernetesConfig(t *testing.T, addr, jwtPath string) string {
	t.Helper()

	return writeConfig(t, fmt.Sprintf(`vault:
  addr: '%s'
  auth_method: 'kubernetes'
  k8s_mount: 'kubernetes'
  k8s_role: 'my-sshsigner-role'
  jwt_path: '%s'
  mount_point: 'sshca'
  role_name: 'signhost'
`, addr, jwtPath))
}

func writeJWT(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("writing jwt: %v", err)
	}
	return path
}

func execute(t *testing.T, args ...string) (string, error) {
	t.Helper()

	stdout := &bytes.Buffer{}
	cmd := newRootCommand(stdout)
	cmd.SetArgs(args)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	err := cmd.ExecuteContext(context.Background())
	return stdout.String(), err
}

func TestSignJSONOutputIsExact(t *testing.T) {
	vault := newFakeVault(t)

	stdout, err := execute(t,
		"--config", approleConfig(t, vault.server.URL),
		"--valid_principals", "host,host.example.net,192.0.2.1",
		"--ttl", "87600h",
		"--public_key", testPublicKey,
		"--json",
	)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	want := fmt.Sprintf("{\"signed_key\":%q}\n", testSignedKey)
	if stdout != want {
		t.Fatalf("stdout = %q, want %q", stdout, want)
	}

	var decoded map[string]string
	if err := json.Unmarshal([]byte(stdout), &decoded); err != nil {
		t.Fatalf("stdout is not valid JSON: %v", err)
	}
	if decoded["signed_key"] != testSignedKey {
		t.Fatalf("signed_key = %q", decoded["signed_key"])
	}
}

func TestSignSendsExpectedVaultRequests(t *testing.T) {
	vault := newFakeVault(t)
	principals := "host,host.example.net,192.0.2.1"

	if _, err := execute(t,
		"--config", approleConfig(t, vault.server.URL),
		"--valid_principals", principals,
		"--ttl", "87600h",
		"--public_key", testPublicKey,
		"--json",
	); err != nil {
		t.Fatalf("run: %v", err)
	}

	if vault.login.path != "/v1/auth/approle/login" {
		t.Errorf("login path = %q", vault.login.path)
	}
	if vault.login.body["role_id"] != "role-id-value" {
		t.Errorf("login body = %v", vault.login.body)
	}
	if _, ok := vault.login.body["secret_id"]; ok {
		t.Errorf("login body carried a secret_id: %v", vault.login.body)
	}
	if vault.sign.path != "/v1/sshca/sign/signhost" {
		t.Errorf("sign path = %q", vault.sign.path)
	}
	if vault.sign.token != testToken {
		t.Errorf("X-Vault-Token = %q", vault.sign.token)
	}
	if vault.sign.body["cert_type"] != "host" {
		t.Errorf("cert_type = %q", vault.sign.body["cert_type"])
	}
	// Vault wants the principals as the comma-separated string it was given.
	if vault.sign.body["valid_principals"] != principals {
		t.Errorf("valid_principals = %q, want %q", vault.sign.body["valid_principals"], principals)
	}
	if vault.sign.body["public_key"] != testPublicKey {
		t.Errorf("public_key = %q", vault.sign.body["public_key"])
	}
	if vault.sign.body["ttl"] != "87600h" {
		t.Errorf("ttl = %q", vault.sign.body["ttl"])
	}
}

func TestSignDefaultTTLAndPlainOutput(t *testing.T) {
	vault := newFakeVault(t)

	stdout, err := execute(t,
		"--config", approleConfig(t, vault.server.URL),
		"--valid_principals", "host",
		"--public_key", testPublicKey,
	)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if stdout != testSignedKey+"\n" {
		t.Fatalf("stdout = %q", stdout)
	}
	if vault.sign.body["ttl"] != defaultTTL {
		t.Fatalf("ttl = %q, want %q", vault.sign.body["ttl"], defaultTTL)
	}
}

func TestKubernetesAuthSignsWithServiceAccountToken(t *testing.T) {
	vault := newFakeVault(t)
	jwtPath := writeJWT(t, "jwt-token-value\n")

	stdout, err := execute(t,
		"--config", kubernetesConfig(t, vault.server.URL, jwtPath),
		"--valid_principals", "host",
		"--public_key", testPublicKey,
		"--json",
	)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(stdout, testSignedKey) {
		t.Fatalf("stdout = %q", stdout)
	}
	if vault.login.path != "/v1/auth/kubernetes/login" {
		t.Errorf("login path = %q", vault.login.path)
	}
	if vault.login.body["role"] != "my-sshsigner-role" {
		t.Errorf("role = %q", vault.login.body["role"])
	}
	if vault.login.body["jwt"] != "jwt-token-value" {
		t.Errorf("jwt = %q", vault.login.body["jwt"])
	}
}

func TestFailures(t *testing.T) {
	tests := []struct {
		name        string
		config      func(t *testing.T, vault *fakeVault) string
		prepare     func(vault *fakeVault)
		wantErr     []string
		wantNoSign  bool
		wantNoLogin bool
	}{
		{
			name:       "approle login rejected",
			config:     func(t *testing.T, v *fakeVault) string { return approleConfig(t, v.server.URL) },
			prepare:    func(v *fakeVault) { v.authStatus = http.StatusForbidden },
			wantErr:    []string{"approle login", "403", "permission denied"},
			wantNoSign: true,
		},
		{
			name: "kubernetes login rejected",
			config: func(t *testing.T, v *fakeVault) string {
				return kubernetesConfig(t, v.server.URL, writeJWT(t, "jwt-token-value"))
			},
			prepare:    func(v *fakeVault) { v.authStatus = http.StatusForbidden },
			wantErr:    []string{"kubernetes login", "my-sshsigner-role", "kubernetes", "403"},
			wantNoSign: true,
		},
		{
			name: "missing service account token",
			config: func(t *testing.T, v *fakeVault) string {
				return kubernetesConfig(t, v.server.URL, filepath.Join(t.TempDir(), "absent"))
			},
			wantErr:     []string{"reading service account token", "absent"},
			wantNoLogin: true,
			wantNoSign:  true,
		},
		{
			name: "empty service account token",
			config: func(t *testing.T, v *fakeVault) string {
				return kubernetesConfig(t, v.server.URL, writeJWT(t, "  \n"))
			},
			wantErr:     []string{"service account token", "is empty"},
			wantNoLogin: true,
			wantNoSign:  true,
		},
		{
			name: "unknown auth method",
			config: func(t *testing.T, v *fakeVault) string {
				return writeConfig(t, fmt.Sprintf(`vault:
  addr: '%s'
  auth_method: 'oidc'
  mount_point: 'sshca'
  role_name: 'signhost'
`, v.server.URL))
			},
			wantErr:     []string{`unsupported auth_method "oidc"`, "approle", "kubernetes"},
			wantNoLogin: true,
			wantNoSign:  true,
		},
		{
			name:    "sign rejected by vault policy",
			config:  func(t *testing.T, v *fakeVault) string { return approleConfig(t, v.server.URL) },
			prepare: func(v *fakeVault) { v.signStatus = http.StatusForbidden },
			wantErr: []string{"sshca/sign/signhost", "403", "permission denied"},
		},
		{
			name:    "sign response without signed_key",
			config:  func(t *testing.T, v *fakeVault) string { return approleConfig(t, v.server.URL) },
			prepare: func(v *fakeVault) { v.signBody = `{"data":{"serial_number":"42"}}` },
			wantErr: []string{"sshca/sign/signhost", "no data.signed_key"},
		},
		{
			name: "vault does not answer in time",
			config: func(t *testing.T, v *fakeVault) string {
				return writeConfig(t, fmt.Sprintf(`vault:
  addr: '%s'
  role_id: 'role-id-value'
  approle_path: 'approle'
  mount_point: 'sshca'
  role_name: 'signhost'
  timeout: '150ms'
`, v.server.URL))
			},
			prepare: func(v *fakeVault) { v.delay = 2 * time.Second },
			wantErr: []string{"approle login", "timeout"},
		},
		{
			name: "config file missing",
			config: func(t *testing.T, _ *fakeVault) string {
				return filepath.Join(t.TempDir(), "absent.yaml")
			},
			wantErr:     []string{"reading config", "absent.yaml"},
			wantNoLogin: true,
			wantNoSign:  true,
		},
		{
			name: "config missing required key",
			config: func(t *testing.T, v *fakeVault) string {
				return writeConfig(t, fmt.Sprintf(`vault:
  addr: '%s'
  role_id: 'role-id-value'
  approle_path: 'approle'
  role_name: 'signhost'
`, v.server.URL))
			},
			wantErr:     []string{"vault.mount_point is required"},
			wantNoLogin: true,
			wantNoSign:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			vault := newFakeVault(t)
			if test.prepare != nil {
				test.prepare(vault)
			}

			stdout, err := execute(t,
				"--config", test.config(t, vault),
				"--valid_principals", "host",
				"--public_key", testPublicKey,
				"--json",
			)
			if err == nil {
				t.Fatalf("expected an error, got stdout %q", stdout)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want empty on failure", stdout)
			}
			for _, want := range test.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not mention %q", err, want)
				}
			}
			if test.wantNoLogin && vault.login.called {
				t.Errorf("vault login was called")
			}
			if test.wantNoSign && vault.sign.called {
				t.Errorf("vault sign was called")
			}
		})
	}
}

func TestMissingRequiredFlags(t *testing.T) {
	vault := newFakeVault(t)
	config := approleConfig(t, vault.server.URL)

	for _, args := range [][]string{
		{"--config", config, "--valid_principals", "host"},
		{"--config", config, "--public_key", testPublicKey},
	} {
		if _, err := execute(t, args...); err == nil {
			t.Fatalf("expected an error for args %v", args)
		}
	}
}

// Puppet runs the binary with generate(..., combine: true), which dups stderr
// onto stdout: a single byte on stderr corrupts the JSON parsejson() reads.
func TestSuccessWritesNothingToStderr(t *testing.T) {
	vault := newFakeVault(t)

	cmd := exec.Command(os.Args[0],
		"--config", approleConfig(t, vault.server.URL),
		"--valid_principals", "host,host.example.net,192.0.2.1",
		"--ttl", "87600h",
		"--public_key", testPublicKey,
		"--json",
	)
	cmd.Env = append(os.Environ(), subprocessEnv+"=1")

	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	cmd.Stdout, cmd.Stderr = stdout, stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("subprocess failed: %v (stderr %q)", err, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}

	want := fmt.Sprintf("{\"signed_key\":%q}\n", testSignedKey)
	if stdout.String() != want {
		t.Fatalf("stdout = %q, want %q", stdout.String(), want)
	}
}

func TestFailureExitsNonZeroWithMessageOnStderr(t *testing.T) {
	vault := newFakeVault(t)
	vault.signStatus = http.StatusForbidden

	cmd := exec.Command(os.Args[0],
		"--config", approleConfig(t, vault.server.URL),
		"--valid_principals", "host",
		"--public_key", testPublicKey,
		"--json",
	)
	cmd.Env = append(os.Environ(), subprocessEnv+"=1")

	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	cmd.Stdout, cmd.Stderr = stdout, stderr

	err := cmd.Run()
	if err == nil {
		t.Fatalf("expected a non-zero exit, stdout %q", stdout.String())
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() == 0 {
		t.Fatalf("expected a non-zero exit status, got %v", err)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "sshca/sign/signhost") {
		t.Errorf("stderr = %q, want the failing path named", stderr.String())
	}
}
