package fingerprint

import (
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
)

const minAttributes = 3

// DerivePlatformKey derives the platform key used for credential encryption.
//
// If platformKeyFile is provided (for containers/VMs), the key is read from the file.
// Otherwise, it's derived from machine attributes via HMAC-SHA256.
//
// Requires at least 3 non-empty attributes to proceed without a platform key file.
// This prevents weak fingerprints in minimal environments.
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

	// Derive from machine attributes
	attrs, err := CollectMachineAttributes()
	if err != nil {
		return nil, fmt.Errorf("collect machine attributes: %w", err)
	}

	count := attrs.AttributeCount()
	if count < minAttributes {
		return nil, fmt.Errorf(
			"insufficient machine attributes (%d/%d): use --platform-key-file for containers/VMs with limited identity",
			count, minAttributes,
		)
	}

	if count < 5 {
		log.Warn().
			Int("attributes", count).
			Msg("Only partial machine fingerprint available; some attributes could not be collected")
	}

	key := ComputeMachineFingerprint(attrs)
	return key, nil
}

// DerivePlatformKeyWithAttrs is like DerivePlatformKey but also returns the
// collected machine attributes (needed during registration to send to the vault).
func DerivePlatformKeyWithAttrs(platformKeyFile string) ([]byte, *MachineAttributes, error) {
	if platformKeyFile != "" {
		key, err := DerivePlatformKey(platformKeyFile)
		if err != nil {
			return nil, nil, err
		}
		// For file-based keys, return empty attributes (not applicable)
		return key, &MachineAttributes{}, nil
	}

	attrs, err := CollectMachineAttributes()
	if err != nil {
		return nil, nil, fmt.Errorf("collect machine attributes: %w", err)
	}

	count := attrs.AttributeCount()
	if count < minAttributes {
		return nil, nil, fmt.Errorf(
			"insufficient machine attributes (%d/%d): use --platform-key-file for containers/VMs",
			count, minAttributes,
		)
	}

	key := ComputeMachineFingerprint(attrs)
	return key, attrs, nil
}
