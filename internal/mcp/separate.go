package mcp

import (
	"runtime"

	"github.com/vettid/vettid-agent/internal/leash/request"
)

// The separate-account mode's codes and texts (AGENT-PLAN §2 AG14, §11,
// 0.1.16; the codes service_not_running and versions_differ are the
// lead's call within §6 A3.10a).
const (
	CodeServiceNotRunning       = "service_not_running"
	CodeVersionsDiffer          = "versions_differ"
	CodeSeparateAccountRequired = "separate_account_required"

	// TextNoServiceWindows and TextNoServicePOSIX: the stub, any tool
	// when the channel is missing ("No service").
	TextNoServiceWindows = "The connector service is not running. Start it from Services, or ask your administrator to run `vettid-agent install --upgrade`."
	TextNoServicePOSIX   = "The connector service is not running. Tell your administrator."
	// TextVersionsDiffer: the stub, when the service is another version.
	TextVersionsDiffer = "The connector service and this program are different versions. Ask your administrator to run `vettid-agent install --upgrade`."
	// TextSeparateAccountRequired: a run or proxy tool of the connector
	// that runs in the agent's account, where the mode exists;
	// TextSeparateAccountNotHere where it does not yet. The run and
	// proxy tools come with A3.8b and A3.9.
	TextSeparateAccountRequired = "Running programs and opening proxies with a secret need the connector installed in its own account. Ask your administrator to run `vettid-agent install`, then try again."
	TextSeparateAccountNotHere  = "Running programs and opening proxies with a secret are not available on this system yet."
	// TextRunsOff: status of the connector that runs in the agent's
	// account.
	TextRunsOff = "Runs and proxies are off: the connector runs in this agent's account."
)

// NoService is the stub's answer to every tool when its channel is
// missing, or isn't the service's.
func NoService() *request.Error {
	if runtime.GOOS == "windows" {
		return &request.Error{Code: CodeServiceNotRunning, Text: TextNoServiceWindows}
	}
	return &request.Error{Code: CodeServiceNotRunning, Text: TextNoServicePOSIX}
}

// VersionsDiffer is the stub's answer to every tool when the service
// runs another version.
func VersionsDiffer() *request.Error {
	return &request.Error{Code: CodeVersionsDiffer, Text: TextVersionsDiffer}
}
