package sshd

import (
	"fmt"
	"strings"
)

const maxUsernameLength = 255
const maxTargetLength = 255
const routeSep = ":"

// Route is the parsed form of the "user:target" SSH username convention.
type Route struct {
	User   string
	Target string
}

// ParseUsername splits raw ("user:target") into a Route.
func ParseUsername(raw string) (Route, error) {
	user, target, found := strings.Cut(raw, routeSep)
	if !found {
		return Route{}, fmt.Errorf("sshd.ParseUsername: invalid format")
	}

	if user == "" {
		return Route{}, fmt.Errorf("sshd.ParseUsername: empty username")
	}

	if target == "" {
		return Route{}, fmt.Errorf("sshd.ParseUsername: empty target")
	}

	if len(user) > maxUsernameLength {
		return Route{}, fmt.Errorf("sshd.ParseUsername: username exceeds %d chars", maxUsernameLength)
	}

	if len(target) > maxTargetLength {
		return Route{}, fmt.Errorf("sshd.ParseUsername: target exceeds %d chars", maxTargetLength)
	}

	return Route{User: user, Target: target}, nil
}
