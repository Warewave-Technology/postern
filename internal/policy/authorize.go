// Package policy answers one question: may this user reach this target, and
// as which OS account?
package policy

import (
	"regexp"
	"slices"

	"github.com/warewave/postern/internal/model"
)

var osUserNamePatternRegex = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

type Decision struct {
	Allowed bool

	OSUser string

	Reason string
}

// Authorize decides whether u may open a session on t, and as which OS user.
func Authorize(u model.User, t model.Target, requested string) Decision {
	for _, role := range u.Roles {
		if slices.Contains(role.Targets, t.Name) {
			if !validateOSUserName(u.OSUser) {
				return Decision{Allowed: false, Reason: "policy.Authorize: OSUser name violation"}
			}

			if u.OSUser == "root" {
				return Decision{Allowed: false, Reason: "policy.Authorize: root access violation"}
			}

			if requested != "" {
				if u.OSUser == requested {
					return Decision{Allowed: true, OSUser: u.OSUser}
				}

				return Decision{Allowed: false, Reason: "policy.Authorize: identitiy injection access violation"}
			}

			return Decision{Allowed: true, OSUser: u.OSUser}
		}
	}

	return Decision{Allowed: false, Reason: "policy.Authorize: default access denied"}
}

func validateOSUserName(osUser string) bool {
	return osUserNamePatternRegex.MatchString(osUser)
}
