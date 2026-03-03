package tun

import "fmt"

func requireLinuxRouteOps(goos string) error {
	if goos == "linux" {
		return nil
	}
	return fmt.Errorf("TUN auto-route is only supported on linux")
}
