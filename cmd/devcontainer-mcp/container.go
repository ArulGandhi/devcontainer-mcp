package main

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

//go:embed Containerfile
var containerfile []byte

type containerSpec struct {
	podman    string
	name      string
	image     string
	memory    string
	pidsLimit string
	rebuild   bool
}

// containerCmd handles `devcontainer-mcp container up`.
func containerCmd(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "up" {
		return errors.New("usage: devcontainer-mcp container up [flags]")
	}
	fs := flag.NewFlagSet("container up", flag.ContinueOnError)
	var spec containerSpec
	fs.StringVar(&spec.podman, "podman", "podman", "podman binary")
	fs.StringVar(&spec.name, "name", "devbox", "container name")
	fs.StringVar(&spec.image, "image", "localhost/devbox:latest", "image tag to build and run")
	fs.StringVar(&spec.memory, "memory", "2g", "memory limit for the container")
	fs.StringVar(&spec.pidsLimit, "pids-limit", "512", "process limit for the container")
	fs.BoolVar(&spec.rebuild, "rebuild", false, "rebuild the image even if it exists")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	return containerUp(ctx, spec, stdout)
}

func podmanRun(ctx context.Context, bin string, args ...string) (string, error) {
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("%s %s: %w: %s", bin, strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return out.String(), nil
}

func containerUp(ctx context.Context, spec containerSpec, stdout io.Writer) error {
	if strings.HasPrefix(spec.name, "-") || strings.ContainsAny(spec.name, " \t\r\n") || spec.name == "" {
		return fmt.Errorf("container name %q is not valid", spec.name)
	}
	if _, err := exec.LookPath(spec.podman); err != nil {
		return fmt.Errorf("podman is not installed or not on PATH (%v); install it from https://podman.io/docs/installation", err)
	}

	if _, err := podmanRun(ctx, spec.podman, "image", "exists", spec.image); err != nil || spec.rebuild {
		dir, err := os.MkdirTemp("", "devcontainer-mcp-build-")
		if err != nil {
			return fmt.Errorf("build directory: %w", err)
		}
		defer os.RemoveAll(dir)
		if err := os.WriteFile(filepath.Join(dir, "Containerfile"), containerfile, 0o600); err != nil {
			return fmt.Errorf("write Containerfile: %w", err)
		}
		fmt.Fprintf(stdout, "building %s (downloads Debian and bun, takes a minute)\n", spec.image)
		if _, err := podmanRun(ctx, spec.podman, "build", "--tag", spec.image, "--file", filepath.Join(dir, "Containerfile"), dir); err != nil {
			return fmt.Errorf("build image: %w", err)
		}
	}

	state, err := podmanRun(ctx, spec.podman, "container", "inspect", "--format", "{{.State.Status}}", spec.name)
	switch state = strings.TrimSpace(state); {
	case err != nil:
		if _, err := podmanRun(ctx, spec.podman, "run", "--detach", "--name", spec.name, "--init",
			"--restart=unless-stopped", "--memory", spec.memory, "--pids-limit", spec.pidsLimit,
			"--security-opt", "no-new-privileges", spec.image); err != nil {
			return fmt.Errorf("create container: %w", err)
		}
		fmt.Fprintf(stdout, "container %s created and running\n", spec.name)
	case state == "running":
		fmt.Fprintf(stdout, "container %s is already running\n", spec.name)
	default:
		if _, err := podmanRun(ctx, spec.podman, "start", spec.name); err != nil {
			return fmt.Errorf("start container: %w", err)
		}
		fmt.Fprintf(stdout, "container %s was %s; started it\n", spec.name, state)
	}
	return nil
}
