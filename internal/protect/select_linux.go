//go:build linux

package protect

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// TPM device paths: the resource manager the protector uses, and the
// raw device whose presence alone also means "this computer has a TPM".
// Tests replace them, and openTPMDevice.
var (
	tpmRMDevice   = DefaultTPMDevice
	tpmRawDevice  = "/dev/tpm0"
	openTPMDevice = func(path string) (transport.TPMCloser, error) { return linuxtpm.Open(path) }
)

// ChooseProtector picks the protector for a new state file (AGENT-PLAN
// §2 AG3):
//
//   - no TPM device at all (neither /dev/tpmrm0 nor /dev/tpm0): the
//     passphrase protector, with the reason, and no error;
//   - a TPM that works (the resource manager opens and creates its
//     storage root key, retrying transient answers): the TPM protector;
//   - a TPM that is present but does not work (permission denied, no
//     resource manager, an owner password, failure mode, still busy
//     after the retries): an error naming the cause and the fix, unless
//     opts.AllowPassphraseFallback is set (the operator asked for a
//     passphrase), in which case the passphrase protector with that
//     cause as the reason.
func ChooseProtector(opts ChooseOptions) (Choice, error) {
	passphrase := func(reason string) Choice {
		return Choice{Protector: PassphraseName, Reason: reason + "; using a passphrase"}
	}
	rm, raw := exists(tpmRMDevice), exists(tpmRawDevice)
	if !rm && !raw {
		return passphrase(fmt.Sprintf("no TPM found (neither %s nor %s exists)", tpmRMDevice, tpmRawDevice)), nil
	}
	err := tryTPM(rm)
	if err == nil {
		return Choice{Protector: TPMName, Reason: "TPM 2.0 at " + tpmRMDevice, MachineBound: true}, nil
	}
	if opts.AllowPassphraseFallback {
		return passphrase(err.Error()), nil
	}
	return Choice{}, fmt.Errorf("%w; or choose a passphrase instead (not bound to this computer)", err)
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return !errors.Is(err, fs.ErrNotExist)
}

// tryTPM checks that the resource manager opens and creates the storage
// root key.
func tryTPM(rmExists bool) error {
	if !rmExists {
		return fmt.Errorf("a TPM is present (%s) but not its resource manager %s: use a kernel with the TPM resource manager (Linux 4.12 or later)", tpmRawDevice, tpmRMDevice)
	}
	return withRetry(func() error {
		tpm, err := openTPMDevice(tpmRMDevice)
		if err != nil {
			return openError(tpmRMDevice, err)
		}
		defer tpm.Close()
		k, err := createSRKFn(tpm)
		if err != nil {
			return describeSRKError(err)
		}
		flush(tpm, k.handle)
		return nil
	})
}

// describeSRKError adds the cause and the fix to a failure to create the
// storage root key; transient codes pass through for withRetry.
func describeSRKError(err error) error {
	switch {
	case isTransient(err):
		return err
	case errors.Is(err, tpm2.TPMRCBadAuth), errors.Is(err, tpm2.TPMRCAuthFail), errors.Is(err, tpm2.TPMRCLockout):
		return fmt.Errorf("the TPM's owner (storage) hierarchy has a password or is locked out, so the connector cannot create its storage key: clear the owner password (for example with `tpm2_changeauth -c owner`) (%v)", err)
	case errors.Is(err, tpm2.TPMRCFailure):
		return fmt.Errorf("the TPM is in failure mode: restart the computer; if it persists, check the TPM in the firmware settings (%v)", err)
	default:
		return fmt.Errorf("the TPM did not create its storage key (%v)", err)
	}
}
