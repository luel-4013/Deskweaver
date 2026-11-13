package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/luel-4013/deskweaver/internal/model"
	"gopkg.in/yaml.v3"
)

const answersSchema = "deskweaver.answers/v1"
const maxAnswersBytes = 1 << 20

type answersEnvelope struct {
	Schema        string `yaml:"schema"`
	model.Answers `yaml:",inline"`
}

// loadAnswers reads a reviewed answers file. Relative project and output paths
// are resolved against the answers file, not the caller's working directory, so
// a saved decision set can be replayed from anywhere.
func loadAnswers(path string) (model.Answers, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return model.Answers{}, fmt.Errorf("resolve answers path: %w", err)
	}
	st, err := os.Stat(abs)
	if err != nil {
		return model.Answers{}, fmt.Errorf("answers file: %w", err)
	}
	if !st.Mode().IsRegular() {
		return model.Answers{}, fmt.Errorf("answers path is not a regular file: %s", abs)
	}
	if st.Size() > maxAnswersBytes {
		return model.Answers{}, fmt.Errorf("answers file is larger than %d bytes", maxAnswersBytes)
	}
	f, err := os.Open(abs)
	if err != nil {
		return model.Answers{}, fmt.Errorf("open answers file: %w", err)
	}
	defer f.Close()
	dec := yaml.NewDecoder(io.LimitReader(f, maxAnswersBytes+1))
	dec.KnownFields(true)
	var env answersEnvelope
	if err := dec.Decode(&env); err != nil {
		if errors.Is(err, io.EOF) {
			return model.Answers{}, errors.New("answers file is empty")
		}
		return model.Answers{}, fmt.Errorf("parse answers file: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return model.Answers{}, errors.New("answers file must contain exactly one YAML document")
		}
		return model.Answers{}, fmt.Errorf("parse answers file: %w", err)
	}
	if env.Schema != answersSchema {
		return model.Answers{}, fmt.Errorf("answers schema must be %q, got %q", answersSchema, env.Schema)
	}
	base := filepath.Dir(abs)
	env.ProjectPath = resolveFrom(base, env.ProjectPath)
	env.OutputDir = resolveFrom(base, env.OutputDir)
	env.Targets = cleanValues(env.Targets)
	env.Formats = cleanValues(env.Formats)
	env.Profile = strings.ToLower(strings.TrimSpace(env.Profile))
	env.Sensitivity = strings.ToLower(strings.TrimSpace(env.Sensitivity))
	env.Network = strings.ToLower(strings.TrimSpace(env.Network))
	env.Privilege = strings.ToLower(strings.TrimSpace(env.Privilege))
	env.Candidate = strings.ToLower(strings.TrimSpace(env.Candidate))
	env.Framework = strings.TrimSpace(env.Framework)
	if env.ProjectPath == "" {
		return model.Answers{}, errors.New("answers file must set project_path")
	}
	return env.Answers, nil
}

func resolveFrom(base, p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			if p == "~" {
				p = home
			} else {
				p = filepath.Join(home, p[2:])
			}
		}
	}
	p = os.ExpandEnv(p)
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Clean(filepath.Join(base, p))
}

func cleanValues(in []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, v := range in {
		for _, part := range strings.Split(v, ",") {
			part = strings.ToLower(strings.TrimSpace(part))
			if part == "" || seen[part] {
				continue
			}
			seen[part] = true
			out = append(out, part)
		}
	}
	return out
}
