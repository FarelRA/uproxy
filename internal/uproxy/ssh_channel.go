package uproxy

import (
	"fmt"

	"golang.org/x/crypto/ssh"
)

// OpenSSHChannel opens an SSH channel of the specified type and automatically
// discards incoming requests. This is a common pattern used across TCP, UDP,
// and TUN tunnels.
func OpenSSHChannel(client *ssh.Client, channelType string) (ssh.Channel, error) {
	channel, reqs, err := client.OpenChannel(channelType, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s channel: %w", channelType, err)
	}

	// Discard incoming requests in a separate goroutine
	go ssh.DiscardRequests(reqs)

	return channel, nil
}
