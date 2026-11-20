# sshsignhost

Vault-backed SSH host certificate signing helper for Puppet.

Puppet's `profiles::ssh::sign` class calls the binary server-side during catalog
compilation via `generate()`, then feeds its stdout to `parsejson()`:

```
/usr/local/bin/sshsignhost --valid_principals "host,fqdn,ip" --ttl 87600h \
  --public_key "ssh-rsa AAAA..." --json
```

`generate()` runs with `combine: true`, so stderr is spliced into stdout.
On success the process writes only the JSON document to stdout and nothing at
all to stderr; any failure prints a message naming the cause to stderr and
exits non-zero, which aborts the compile cleanly instead of yielding a parse
error.

## Usage

| Flag | Default | Required |
|---|---|---|
| `--public_key` | — | yes |
| `--valid_principals` (comma-separated, forwarded to Vault verbatim) | — | yes |
| `--ttl` | `87600h` | no |
| `--json` | `false` | no |
| `--config` | `/opt/sshsignhost/config.yaml` | no |

With `--json`, stdout is exactly:

```json
{"signed_key": "ssh-rsa-cert-v01@openssh.com AAAA..."}
```

Without it, the raw `signed_key` value plus a newline.

## Configuration

```yaml
vault:
  addr: 'https://vault.example.com:8200'
  auth_method: 'approle'        # or 'kubernetes'
  mount_point: 'sshca'
  role_name: 'signhost'
  # auth_method: approle
  role_id: '...'
  approle_path: 'approle'
  # auth_method: kubernetes
  k8s_mount: 'kubernetes'
  k8s_role: 'my-sshsigner-role'
  jwt_path: '/var/run/secrets/kubernetes.io/serviceaccount/token'
  # optional
  tls_skip_verify: true         # default true
  timeout: '15s'                # default 15s
```

`tls_skip_verify` defaults to `true` to match the Python helper this replaces
(`verify=False`); flip it to `false` once Vault's listeners present trusted
certificates. `timeout` bounds every Vault call so a black-holed Vault cannot
hang a catalog compile forever.

## Build

```bash
make build             # -> dist/sshsignhost
make test
make integration-test  # signs a host key against a dev-mode Vault in a container
make snapshot          # goreleaser: binaries, RPM and archives into dist/
```

Releases are driven entirely by goreleaser in GitHub Actions on a `v*` tag: the
RPM (`/usr/local/bin/sshsignhost` plus bash/zsh/fish completions), the raw
`sshsignhost-<os>-<arch>` binaries, tarballs and a signed `checksums.txt` are
attached to the GitHub release; the puppetserver-compiler initContainer fetches
the raw binaries.
