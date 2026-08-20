package rules

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ggeorgeazevedo/threatdiff/internal/config"
)

//go:embed builtin/*.yaml
var builtinFS embed.FS

// LoadBuiltin returns the rule packs compiled into the binary. They are
// embedded rather than read from disk so `threatdiff scan` works in a
// scratch container with nothing but the binary.
func LoadBuiltin() ([]*Pack, error) {
	entries, err := builtinFS.ReadDir("builtin")
	if err != nil {
		return nil, fmt.Errorf("reading embedded rules: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	packs := make([]*Pack, 0, len(names))
	for _, n := range names {
		data, err := builtinFS.ReadFile("builtin/" + n)
		if err != nil {
			return nil, fmt.Errorf("reading embedded rule pack %s: %w", n, err)
		}
		p, err := decodePack(n, data)
		if err != nil {
			return nil, err
		}
		packs = append(packs, p)
	}
	return packs, nil
}

// LoadPath loads a rule pack file, or every *.yaml/*.yml/*.json pack in a
// directory (recursively).
func LoadPath(p string) ([]*Pack, error) {
	info, err := os.Stat(p)
	if err != nil {
		return nil, fmt.Errorf("rules path %s: %w", p, err)
	}
	if !info.IsDir() {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", p, err)
		}
		pk, err := decodePack(p, data)
		if err != nil {
			return nil, err
		}
		return []*Pack{pk}, nil
	}

	var files []string
	err = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") && path != p {
				return fs.SkipDir
			}
			return nil
		}
		switch strings.ToLower(filepath.Ext(d.Name())) {
		case ".yaml", ".yml", ".json":
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking %s: %w", p, err)
	}
	sort.Strings(files)
	if len(files) == 0 {
		return nil, fmt.Errorf("no rule packs (*.yaml, *.yml, *.json) found under %s", p)
	}

	packs := make([]*Pack, 0, len(files))
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", f, err)
		}
		pk, err := decodePack(f, data)
		if err != nil {
			return nil, err
		}
		packs = append(packs, pk)
	}
	return packs, nil
}

func decodePack(name string, data []byte) (*Pack, error) {
	var p Pack
	var err error
	if strings.HasSuffix(strings.ToLower(name), ".json") {
		err = config.UnmarshalJSON(data, &p)
	} else {
		err = config.UnmarshalYAML(data, &p)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if p.Name == "" {
		p.Name = strings.TrimSuffix(filepath.Base(name), filepath.Ext(name))
	}
	if len(p.Rules) == 0 {
		return nil, fmt.Errorf("%s: rule pack contains no rules", name)
	}
	return &p, nil
}

// Default builds the standard rule set: the embedded packs, optionally
// extended or overridden by user packs found at extraPaths.
func Default(extraPaths ...string) (*Set, error) {
	packs, err := LoadBuiltin()
	if err != nil {
		return nil, err
	}
	for _, p := range extraPaths {
		if p == "" {
			continue
		}
		more, err := LoadPath(p)
		if err != nil {
			return nil, err
		}
		packs = append(packs, more...)
	}
	return Compile(packs...)
}
