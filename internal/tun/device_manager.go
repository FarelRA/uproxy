package tun

import (
	"fmt"
	"log/slog"
	"os/exec"
	"runtime"

	"github.com/songgao/water"
)

// DeviceManager manages the lifecycle of a TUN device.
type DeviceManager struct {
	device *water.Interface
	config *Config
}

// NewDeviceManager creates a new device manager and initializes the TUN device.
func NewDeviceManager(cfg *Config) (*DeviceManager, error) {
	device, err := CreateTUN(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN device: %w", err)
	}

	return &DeviceManager{
		device: device,
		config: cfg,
	}, nil
}

// Read reads a packet from the TUN device.
func (dm *DeviceManager) Read(buf []byte) (int, error) {
	return dm.device.Read(buf)
}

// Write writes a packet to the TUN device.
func (dm *DeviceManager) Write(packet []byte) (int, error) {
	return dm.device.Write(packet)
}

// Name returns the name of the TUN device.
func (dm *DeviceManager) Name() string {
	return dm.device.Name()
}

// Close closes the TUN device and removes it from the system.
func (dm *DeviceManager) Close() error {
	if dm.device == nil {
		return nil
	}

	deviceName := dm.device.Name()

	// Close the file descriptor first
	if err := dm.device.Close(); err != nil {
		slog.Warn("Failed to close TUN device file descriptor", "device", deviceName, "error", err)
	}

	// Explicitly delete the TUN device from the system
	// This ensures the device is fully removed and can be recreated
	if err := deleteTUNDevice(deviceName); err != nil {
		slog.Warn("Failed to delete TUN device", "device", deviceName, "error", err)
		// Don't return error - device might already be gone
	}

	dm.device = nil
	return nil
}

// deleteTUNDevice removes a TUN device from the system
func deleteTUNDevice(deviceName string) error {
	switch runtime.GOOS {
	case "linux":
		// Use ip link delete to remove the device
		cmd := exec.Command("ip", "link", "delete", deviceName)
		if output, err := cmd.CombinedOutput(); err != nil {
			// Check if device doesn't exist (which is fine)
			if string(output) == "" || exec.Command("ip", "link", "show", deviceName).Run() != nil {
				slog.Debug("TUN device already deleted or doesn't exist", "device", deviceName)
				return nil
			}
			return fmt.Errorf("failed to delete TUN device: %w, output: %s", err, output)
		}
		slog.Info("TUN device deleted", "device", deviceName)
		return nil
	case "darwin":
		// On macOS, closing the file descriptor should be enough
		// The device is automatically removed when the last reference is closed
		slog.Debug("TUN device cleanup (macOS)", "device", deviceName)
		return nil
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}
