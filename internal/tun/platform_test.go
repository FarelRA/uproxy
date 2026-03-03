package tun

import "testing"

func TestRequireLinuxRouteOps(t *testing.T) {
	if err := requireLinuxRouteOps("linux"); err != nil {
		t.Fatalf("expected linux to be supported, got error: %v", err)
	}

	err := requireLinuxRouteOps("darwin")
	if err == nil {
		t.Fatal("expected non-linux platform to be rejected")
	}
	if err.Error() != "TUN auto-route is only supported on linux" {
		t.Fatalf("unexpected error message: %v", err)
	}
}
