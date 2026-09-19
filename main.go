package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

var version = "dev"

type options struct {
	configPath      string
	publicKey       string
	validPrincipals string
	ttl             string
	jsonOutput      bool
}

type signedKeyOutput struct {
	SignedKey string `json:"signed_key"`
}

func newRootCommand(stdout io.Writer) *cobra.Command {
	opts := &options{}

	cmd := &cobra.Command{
		Use:     "sshsignhost",
		Short:   "Sign an SSH host certificate with Vault",
		Version: version,
		// Puppet's generate() splices stderr into stdout, so usage and error
		// text must never be emitted by cobra itself.
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.Context(), stdout, opts)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&opts.configPath, "config", defaultConfigPath, "path to the YAML config file")
	flags.StringVar(&opts.publicKey, "public_key", "", "SSH public key as a string")
	flags.StringVar(&opts.validPrincipals, "valid_principals", "", "comma-separated list of valid principals")
	flags.StringVar(&opts.ttl, "ttl", defaultTTL, "certificate time-to-live")
	flags.BoolVar(&opts.jsonOutput, "json", false, `emit {"signed_key": "..."} on stdout`)

	if err := cmd.MarkFlagRequired("public_key"); err != nil {
		panic(err)
	}
	if err := cmd.MarkFlagRequired("valid_principals"); err != nil {
		panic(err)
	}

	return cmd
}

func run(ctx context.Context, stdout io.Writer, opts *options) error {
	cfg, err := loadConfig(opts.configPath)
	if err != nil {
		return err
	}

	client, err := newVaultClient(cfg)
	if err != nil {
		return err
	}

	token, err := client.authenticate(ctx)
	if err != nil {
		return err
	}

	signedKey, err := client.signHostKey(ctx, token, opts.publicKey, opts.validPrincipals, opts.ttl)
	if err != nil {
		return err
	}

	if !opts.jsonOutput {
		_, err = fmt.Fprintln(stdout, signedKey)
		return err
	}

	encoded, err := json.Marshal(signedKeyOutput{SignedKey: signedKey})
	if err != nil {
		return fmt.Errorf("encoding signed key as JSON: %w", err)
	}
	_, err = fmt.Fprintln(stdout, string(encoded))
	return err
}

func main() {
	if err := newRootCommand(os.Stdout).Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "sshsignhost: %v\n", err)
		os.Exit(1)
	}
}
