# sshsignhost

Signs SSH host public keys with a [Vault](https://www.vaultproject.io/) (or
OpenBao) SSH CA and prints the resulting host certificate. It is designed to be
called from Puppet's `generate()` function during catalog compilation, so a
Puppet server can hand each node a CA-signed host certificate, but it works as
a standalone CLI too.

It authenticates to Vault with AppRole or Kubernetes auth, then calls
`POST /v1/<mount_point>/sign/<role_name>` with `cert_type: host`.

## Install

Download a release from
[GitHub releases](https://github.com/IUCLabs/sshsignhost/releases):

- `sshsignhost-<version>-1.<arch>.rpm` installs `/usr/local/bin/sshsignhost`
  plus bash/zsh/fish completions.
- `sshsignhost-<os>-<arch>` is the raw binary (linux/darwin, amd64/arm64).
- `sshsignhost_<version>_<os>_<arch>.tar.gz` holds the binary, README and
  completions.

Verify downloads against `checksums.txt`, which is signed with a detached GPG
signature (`checksums.txt.sig`):

```bash
gpg --verify checksums.txt.sig checksums.txt
sha256sum --check --ignore-missing checksums.txt
```

Or build from source (Go per `go.mod`):

```bash
git clone https://github.com/IUCLabs/sshsignhost.git
cd sshsignhost
make build    # -> dist/sshsignhost
make install  # go install into $GOPATH/bin
```

## Usage

```bash
sshsignhost --valid_principals "host,host.example.com" --ttl 87600h \
  --public_key "ssh-ed25519 AAAA..." --json
```

| Flag | Default | Required |
|---|---|---|
| `--public_key` | — | yes |
| `--valid_principals` (comma-separated, forwarded to Vault verbatim) | — | yes |
| `--ttl` | `87600h` | no |
| `--json` | `false` | no |
| `--config` | `/opt/sshsignhost/config.yaml` | no |
| `--version` / `-v` (print the version and exit) | — | no |

With `--json`, stdout is exactly this compact JSON (no whitespace around `:`)
followed by a single newline:

```json
{"signed_key":"ssh-ed25519-cert-v01@openssh.com AAAA..."}
```

Without it, the raw `signed_key` value plus a newline.

On success the process writes only that output to stdout and nothing at all to
stderr. Any failure prints a message naming the cause to stderr and exits
non-zero. A Vault response without `data.signed_key` is treated as a failure.

### Puppet

`generate()` merges the command's stderr into its stdout, so the
stdout/stderr contract above means the output can go straight to
`parsejson()`, and a failure aborts the compile with a readable error instead
of a parse error. A minimal example:

```puppet
$result = generate(
  '/usr/local/bin/sshsignhost',
  '--public_key', "ssh-ed25519 ${facts['ssh']['ed25519']['key']}",
  '--valid_principals', "${facts['networking']['hostname']},${facts['networking']['fqdn']}",
  '--json',
)
$cert = parsejson($result)['signed_key']
```

## Configuration

```yaml
vault:
  addr: 'https://vault.example.com:8200'
  auth_method: 'approle'        # or 'kubernetes'; default approle
  mount_point: 'ssh-host-signer'
  role_name: 'my-role'
  # auth_method: approle
  role_id: '...'
  approle_path: 'approle'
  # auth_method: kubernetes
  k8s_mount: 'kubernetes'
  k8s_role: 'my-role'
  jwt_path: '/var/run/secrets/kubernetes.io/serviceaccount/token'  # default
  # optional
  tls_skip_verify: true         # default true
  timeout: '15s'                # default 15s
```

`addr`, `mount_point` and `role_name` are always required. AppRole needs
`role_id` and `approle_path`; it logs in with `role_id` only, so the Vault role
must set `bind_secret_id: false`. Kubernetes needs `k8s_mount` and `k8s_role`
and reads the service account JWT from `jwt_path`.

`tls_skip_verify` defaults to `true`; set it to `false` when Vault presents a
certificate trusted by the host. `timeout` bounds every Vault call so an
unreachable Vault cannot hang a catalog compile.

## Build and test

```bash
make build             # -> dist/sshsignhost
make test
make integration-test  # signs a host key against a dev-mode Vault in a container (docker or podman)
make snapshot          # goreleaser: binaries, RPM and archives into dist/
```

## Releases

Pushing a `v*` tag runs GitHub Actions, where GoReleaser publishes the raw
binaries, tarballs, the RPM and a signed `checksums.txt` to the GitHub release.
