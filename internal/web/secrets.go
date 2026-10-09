package web

import (
	"context"
	"slices"

	"github.com/catchysh/catchy/internal/db"
	"github.com/catchysh/catchy/internal/env"
	"github.com/catchysh/catchy/internal/handler"
)

// MissingSecret is a secret that guards or handlers use but the
// environment doesn't set.
type MissingSecret struct {
	Name   string
	UsedBy []string // e.g. "guard stripe", "handler slack"
}

// MissingSecrets returns the secrets that are used but not set, sorted by
// name. Secrets live in the environment, so one can disappear on any
// restart; guards that need it then refuse hooks and handlers fail.
func MissingSecrets(ctx context.Context, database *db.DB, e env.Env) ([]MissingSecret, error) {
	used := map[string][]string{}
	guards, err := database.ListGuards(ctx)
	if err != nil {
		return nil, err
	}
	for _, g := range guards {
		if g.Secret != "" {
			used[g.Secret] = append(used[g.Secret], "guard "+g.Name)
		}
	}
	dsts, err := database.ListHandlers(ctx)
	if err != nil {
		return nil, err
	}
	for _, dst := range dsts {
		opts, _ := handler.ParseOptions(dst.Options)
		for _, name := range handler.SecretsUsed(opts) {
			used[name] = append(used[name], "handler "+dst.Name)
		}
	}
	var missing []MissingSecret
	for name, by := range used {
		if _, ok := e.Secrets[name]; !ok {
			missing = append(missing, MissingSecret{Name: name, UsedBy: by})
		}
	}
	slices.SortFunc(missing, func(a, b MissingSecret) int {
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}
		return 0
	})
	return missing, nil
}
