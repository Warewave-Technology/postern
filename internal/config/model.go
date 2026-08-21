package config

import (
	"slices"

	"github.com/warewave/postern/internal/model"
)

func (c *Config) ModelUser(name string) (model.User, bool) {
	var user UserConfig

	idx := slices.IndexFunc(c.Users, func(u UserConfig) bool {
		return u.Name == name
	})

	if idx != -1 {
		user = c.Users[idx]
	} else {
		return model.User{}, false
	}

	var roles []model.Role

	for _, role := range user.Roles {
		idx = slices.IndexFunc(c.Roles, func(r RoleConfig) bool {
			return r.Name == role
		})

		if idx != -1 {
			rR := c.Roles[idx]
			roles = append(roles, model.Role{Name: rR.Name, Targets: rR.Targets})
		} else {
			return model.User{Name: user.Name, OSUser: user.OSUser, Roles: roles}, false
		}
	}

	return model.User{Name: user.Name, OSUser: user.OSUser, Roles: roles}, true
}
