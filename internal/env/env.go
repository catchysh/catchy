// Package env reads the variables and secrets set in Catchy's environment:
// CATCHY_VAR_NAME for {{.Vars.NAME}} and CATCHY_SECRET_NAME for
// {{.Secrets.NAME}} in destination templates. Guards use secrets by name too.
// Secrets live only here, typically set by a secret manager, and are never
// stored. Only these prefixes are read, so Catchy's own settings, like
// SESSION_SECRET, stay out of reach.
package env

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const (
	VarPrefix    = "CATCHY_VAR_"
	SecretPrefix = "CATCHY_SECRET_"
)

var nameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

// ValidName reports whether name can name a variable or secret: up to 64
// letters, digits, and _, not starting with a digit.
func ValidName(name string) bool { return nameRe.MatchString(name) }

// Env holds the variables and secrets from the environment, by name without
// the prefix.
type Env struct {
	Vars    map[string]string
	Secrets map[string]string
}

// Load reads CATCHY_VAR_ and CATCHY_SECRET_ entries from environ, as from os.Environ. It
// returns the names it skipped because they can't be used in templates.
func Load(environ []string) (Env, []string) {
	e := Env{Vars: map[string]string{}, Secrets: map[string]string{}}
	var skipped []string
	for _, kv := range environ {
		key, value, _ := strings.Cut(kv, "=")
		for prefix, into := range map[string]map[string]string{VarPrefix: e.Vars, SecretPrefix: e.Secrets} {
			name, ok := strings.CutPrefix(key, prefix)
			if !ok {
				continue
			}
			if !nameRe.MatchString(name) {
				skipped = append(skipped, key)
				continue
			}
			into[name] = value
		}
	}
	sort.Strings(skipped)
	return e, skipped
}

// Secret returns the CATCHY_SECRET_NAME variable, or an error when it isn't
// set.
func (e Env) Secret(name string) (string, error) {
	v, ok := e.Secrets[name]
	if !ok {
		return "", fmt.Errorf("secret %s isn't set: add %s%s to the environment", name, SecretPrefix, name)
	}
	return v, nil
}

// Has reports whether the secret is set.
func (e Env) Has(name string) bool {
	_, ok := e.Secrets[name]
	return ok
}

// SecretNames returns the secrets' names, sorted.
func (e Env) SecretNames() []string {
	names := make([]string, 0, len(e.Secrets))
	for k := range e.Secrets {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// VarNames returns the variables' names, sorted.
func (e Env) VarNames() []string {
	names := make([]string, 0, len(e.Vars))
	for k := range e.Vars {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}
