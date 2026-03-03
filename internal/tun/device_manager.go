package tun

import (
	"fmt"

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

// Close closes the TUN device.
func (dm *DeviceManager) Close() error {
	return dm.device.Close()
}
