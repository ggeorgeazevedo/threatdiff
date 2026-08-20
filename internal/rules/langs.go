package rules

import (
	"path"
	"sort"
	"strings"
)

// Language identifiers understood by the `languages:` field of a rule.
var extLang = map[string]string{
	".go":     "go",
	".py":     "python",
	".pyi":    "python",
	".js":     "javascript",
	".jsx":    "javascript",
	".mjs":    "javascript",
	".cjs":    "javascript",
	".ts":     "typescript",
	".tsx":    "typescript",
	".java":   "java",
	".kt":     "kotlin",
	".kts":    "kotlin",
	".scala":  "scala",
	".rb":     "ruby",
	".erb":    "ruby",
	".rake":   "ruby",
	".php":    "php",
	".cs":     "csharp",
	".c":      "c",
	".h":      "c",
	".cc":     "cpp",
	".cpp":    "cpp",
	".cxx":    "cpp",
	".hpp":    "cpp",
	".rs":     "rust",
	".swift":  "swift",
	".m":      "objc",
	".sh":     "shell",
	".bash":   "shell",
	".zsh":    "shell",
	".ps1":    "powershell",
	".sql":    "sql",
	".tf":     "terraform",
	".tfvars": "terraform",
	".hcl":    "hcl",
	".yaml":   "yaml",
	".yml":    "yaml",
	".json":   "json",
	".toml":   "toml",
	".ini":    "ini",
	".xml":    "xml",
	".html":   "html",
	".htm":    "html",
	".vue":    "vue",
	".svelte": "svelte",
	".css":    "css",
	".scss":   "css",
	".md":     "markdown",
	".proto":  "proto",
	".gradle": "gradle",
	".groovy": "groovy",
	".dart":   "dart",
	".ex":     "elixir",
	".exs":    "elixir",
	".pl":     "perl",
	".lua":    "lua",
	".env":    "dotenv",
}

var nameLang = map[string]string{
	"dockerfile":          "dockerfile",
	"containerfile":       "dockerfile",
	"makefile":            "make",
	"jenkinsfile":         "groovy",
	"gemfile":             "ruby",
	"rakefile":            "ruby",
	"vagrantfile":         "ruby",
	"procfile":            "config",
	"requirements.txt":    "python-deps",
	"pipfile":             "python-deps",
	"pyproject.toml":      "python-deps",
	"poetry.lock":         "lockfile",
	"package.json":        "node-deps",
	"package-lock.json":   "lockfile",
	"yarn.lock":           "lockfile",
	"pnpm-lock.yaml":      "lockfile",
	"go.mod":              "go-deps",
	"go.sum":              "lockfile",
	"cargo.toml":          "rust-deps",
	"cargo.lock":          "lockfile",
	"gemfile.lock":        "lockfile",
	"composer.json":       "php-deps",
	"composer.lock":       "lockfile",
	"pom.xml":             "java-deps",
	"build.gradle":        "java-deps",
	"build.gradle.kts":    "java-deps",
	"go.work":             "go-deps",
	"terraform.tfstate":   "terraform",
	".env":                "dotenv",
	".npmrc":              "config",
	".gitlab-ci.yml":      "ci",
	"codeowners":          "config",
	"docker-compose.yml":  "compose",
	"docker-compose.yaml": "compose",
}

// LanguageOf classifies a path. It checks the exact file name first (so
// `Dockerfile` and `package.json` get their own identity) and then the
// extension. Unrecognised files return "unknown".
func LanguageOf(p string) string {
	base := strings.ToLower(path.Base(p))
	if l, ok := nameLang[base]; ok {
		return l
	}
	// Dockerfile.prod, Dockerfile-ci, etc.
	if strings.HasPrefix(base, "dockerfile") {
		return "dockerfile"
	}
	if strings.HasPrefix(base, ".env") {
		return "dotenv"
	}
	if l, ok := extLang[strings.ToLower(path.Ext(base))]; ok {
		// A YAML file inside .github/workflows is CI, not generic YAML.
		if l == "yaml" && strings.Contains(strings.ToLower(p), ".github/workflows/") {
			return "ci"
		}
		return l
	}
	return "unknown"
}

var extraLanguages = []string{"unknown", "ci", "compose", "config", "lockfile"}

// KnownLanguage reports whether a language identifier is one threatdiff emits.
func KnownLanguage(l string) bool {
	for _, v := range extLang {
		if v == l {
			return true
		}
	}
	for _, v := range nameLang {
		if v == l {
			return true
		}
	}
	for _, v := range extraLanguages {
		if v == l {
			return true
		}
	}
	return false
}

// Languages returns every known language identifier, sorted.
func Languages() []string {
	seen := map[string]bool{}
	for _, v := range extLang {
		seen[v] = true
	}
	for _, v := range nameLang {
		seen[v] = true
	}
	for _, v := range extraLanguages {
		seen[v] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
