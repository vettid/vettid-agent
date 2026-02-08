package fingerprint

import (
	"fmt"
	"os"
)

func DerivePlatformKey(platformKeyFile string) ([]byte, error) {
	// If an explicit platform key file is provided (for containers/VMs), use it
	if platformKeyFile != "" {
		data, err := os.ReadFile(platformKeyFile)
		if err != nil {
			return nil, fmt.Errorf("read platform key file: %w", err)
		}
		if len(data) < 32 {
			return nil, fmt.Errorf("platform key file must be at least 32 bytes")
		}
		return data[:32], nil
	}

	// Otherwise, derive from machine attributes
	attrs, err := CollectMachineAttributes()
	if err != nil {
		return nil, fmt.Errorf("collect machine attributes: %w", err)
	}

	key := ComputeMachineFingerprint(attrs)
	return key, nil
}
