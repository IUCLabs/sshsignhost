package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
)

const maxErrorBody = 4096

type vaultClient struct {
	cfg    vaultConfig
	client *http.Client
}

type authResponse struct {
	Auth struct {
		ClientToken string `json:"client_token"`
	} `json:"auth"`
}

type signResponse struct {
	Data struct {
		SignedKey string `json:"signed_key"`
	} `json:"data"`
}

func newVaultClient(cfg vaultConfig) (*vaultClient, error) {
	timeout, err := cfg.requestTimeout()
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: timeout}).DialContext,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: cfg.skipTLSVerify(), // #nosec G402
		},
	}

	return &vaultClient{cfg: cfg, client: &http.Client{Timeout: timeout, Transport: transport}}, nil
}

func (v *vaultClient) authenticate(ctx context.Context) (string, error) {
	switch v.cfg.AuthMethod {
	case authAppRole:
		return v.loginAppRole(ctx)
	case authKubernetes:
		return v.loginKubernetes(ctx)
	default:
		return "", fmt.Errorf("unsupported auth_method %q: expected %q or %q", v.cfg.AuthMethod, authAppRole, authKubernetes)
	}
}

func (v *vaultClient) loginAppRole(ctx context.Context) (string, error) {
	path := fmt.Sprintf("auth/%s/login", v.cfg.AppRolePath)
	// The Vault role sets bind_secret_id: false, so role_id alone logs in.
	body := map[string]string{"role_id": v.cfg.RoleID}

	token, err := v.login(ctx, path, body)
	if err != nil {
		return "", fmt.Errorf("approle login on mount %q: %w", v.cfg.AppRolePath, err)
	}
	return token, nil
}

func (v *vaultClient) loginKubernetes(ctx context.Context) (string, error) {
	raw, err := os.ReadFile(v.cfg.JWTPath) // #nosec G304
	if err != nil {
		return "", fmt.Errorf("reading service account token %q: %w", v.cfg.JWTPath, err)
	}
	jwt := strings.TrimSpace(string(raw))
	if jwt == "" {
		return "", fmt.Errorf("service account token %q is empty", v.cfg.JWTPath)
	}

	path := fmt.Sprintf("auth/%s/login", v.cfg.K8sMount)
	body := map[string]string{"role": v.cfg.K8sRole, "jwt": jwt}

	token, err := v.login(ctx, path, body)
	if err != nil {
		return "", fmt.Errorf("kubernetes login as role %q on mount %q: %w", v.cfg.K8sRole, v.cfg.K8sMount, err)
	}
	return token, nil
}

func (v *vaultClient) login(ctx context.Context, path string, body map[string]string) (string, error) {
	raw, err := v.post(ctx, path, "", body)
	if err != nil {
		return "", err
	}

	var parsed authResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", fmt.Errorf("decoding login response: %w", err)
	}
	if parsed.Auth.ClientToken == "" {
		return "", errors.New("login response carried no auth.client_token")
	}
	return parsed.Auth.ClientToken, nil
}

func (v *vaultClient) signHostKey(ctx context.Context, token, publicKey, validPrincipals, ttl string) (string, error) {
	path := fmt.Sprintf("%s/sign/%s", v.cfg.MountPoint, v.cfg.RoleName)
	body := map[string]string{
		"cert_type":        "host",
		"public_key":       publicKey,
		"valid_principals": validPrincipals,
		"ttl":              ttl,
	}

	raw, err := v.post(ctx, path, token, body)
	if err != nil {
		return "", fmt.Errorf("signing host key at %q: %w", path, err)
	}

	var parsed signResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", fmt.Errorf("decoding sign response from %q: %w", path, err)
	}
	if parsed.Data.SignedKey == "" {
		return "", fmt.Errorf("sign response from %q carried no data.signed_key", path)
	}
	return parsed.Data.SignedKey, nil
}

func (v *vaultClient) post(ctx context.Context, path, token string, body map[string]string) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("encoding request body: %w", err)
	}

	url := fmt.Sprintf("%s/v1/%s", strings.TrimRight(v.cfg.Addr, "/"), path)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(encoded))
	if err != nil {
		return nil, fmt.Errorf("building request for %s: %w", url, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}

	resp, err := v.client.Do(req)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return nil, fmt.Errorf("timeout after %s waiting for %s", v.client.Timeout, url)
		}
		return nil, fmt.Errorf("requesting %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading response from %s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vault returned HTTP %d: %s", resp.StatusCode, truncate(string(raw)))
	}
	return raw, nil
}

func truncate(body string) string {
	body = strings.TrimSpace(body)
	if len(body) > maxErrorBody {
		return body[:maxErrorBody] + "..."
	}
	return body
}
