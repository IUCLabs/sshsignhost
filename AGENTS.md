# AGENTS.md

## Project Overview

`sshsignhost` signs SSH host certificates with Vault. It is a drop-in
replacement for the Python script Puppet used to render at
`/opt/sshsignhost/sshsignhost`, and is invoked by
`profiles::ssh::sign` (puppet-prod) through `generate()` at
`/usr/local/bin/sshsignhost`.

## Structure

```
main.go          # cobra command, flag surface, stdout rendering
config.go        # YAML config loading, defaults, validation
vault.go         # Vault HTTP client: approle/kubernetes login + sign
main_test.go     # end-to-end tests against an httptest TLS stand-in for Vault
Makefile         # build / test / lint / completions / rpm / version bump
packaging/       # nfpm spec for the RPM
scripts/         # build-rpm.sh (completions + nfpm)
.woodpecker/     # build, test, pre-commit (PR) + release (tag)
```

## Contract with Puppet

- Flags use underscores (`--public_key`, `--valid_principals`), matching the
  argv the manifest builds.
- `--valid_principals` is forwarded to Vault as the comma-separated string it
  was given; it is never split and rejoined.
- `generate()` uses `failonfail: true, combine: true`: stderr is duped onto
  stdout at spawn. On success nothing may reach stderr, or `parsejson()` fails
  and the catalog compile breaks. `TestSuccessWritesNothingToStderr` runs the
  real binary in a subprocess to hold that line.
- A 200 response without `data.signed_key` is a failure, never an empty result.

## Vault

- AppRole: `POST {addr}/v1/auth/{approle_path}/login` with `role_id` only; the
  Vault role sets `bind_secret_id: false`.
- Kubernetes: `POST {addr}/v1/auth/{k8s_mount}/login` with `role` and the JWT
  read from `jwt_path`. There is no fallback between methods -- a rejected
  login or an unknown `auth_method` fails with the cause named.
- Sign: `POST {addr}/v1/{mount_point}/sign/{role_name}` with `X-Vault-Token`
  and `cert_type: host`.

## Known blocker

The Vault ACL policy grants `sshca/sign/host`, but the only role that exists is
`signhost`, so production signs 403 on `sshca/sign/signhost` even though auth
succeeds. That is a terraform-vault fix, not a bug here -- do not change the
requested path.

## TLS

`tls_skip_verify` defaults to `true`, preserving the Python helper's
`verify=False` behaviour, and is a config key so it can be flipped without a
code change once certificates are trusted everywhere.
