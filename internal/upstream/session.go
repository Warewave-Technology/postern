package upstream

import (
	"fmt"

	"golang.org/x/crypto/ssh"
)

// OpenSession opens a "session" channel on the target and returns it along
// with the target's request stream.
func (c *Conn) OpenSession() (ssh.Channel, <-chan *ssh.Request, error) {
	ch, reqs, err := c.client.OpenChannel("session", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("target %s: %w", c.target.Name, err)
	}

	return ch, reqs, nil
}
