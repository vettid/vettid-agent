//go:build linux

package protect

import (
	"errors"
	"fmt"
	"io/fs"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// ChooseProtector picks the TPM protector when the TPM resource manager
// (DefaultTPMDevice) opens and creates its storage root key, and the
// passphrase protector otherwise, with the reason.
func ChooseProtector() Choice {
	return chooseTPM(DefaultTPMDevice, func() (transport.TPMCloser, error) { return linuxtpm.Open(DefaultTPMDevice) })
}

func chooseTPM(device string, open func() (transport.TPMCloser, error)) Choice {
	fallback := func(reason string) Choice {
		return Choice{Protector: PassphraseName, Reason: reason + "; using a passphrase"}
	}
	tpm, err := open()
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fallback(fmt.Sprintf("no TPM found (%s is absent)", device))
	case errors.Is(err, fs.ErrPermission):
		return fallback(fmt.Sprintf("the TPM at %s cannot be opened by this user (permission denied; on most systems the tss group has access)", device))
	case err != nil:
		return fallback(fmt.Sprintf("the TPM at %s cannot be opened (%v)", device, err))
	}
	defer tpm.Close()
	k, err := createSRK(tpm)
	if err != nil {
		return fallback(fmt.Sprintf("the TPM at %s did not create its storage key (%v)", device, err))
	}
	flush(tpm, k.handle)
	return Choice{Protector: TPMName, Reason: "TPM 2.0 at " + device, MachineBound: true}
}
