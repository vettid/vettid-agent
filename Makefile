# Dev-stack tests (AGENT-PLAN §4.8, §6 A2.4 and A3.4): the connector
# against vettid-vault's local dev stack. They are built only with the
# `devstack` tag and do not run in CI. They use the stack that runs for
# VETTID_DEVSTACK_DATA (default: the user cache directory's
# vettid-devstack), or start one from the vettid-vault checkout in
# VETTID_DEVSTACK_SRC (8 GB of memory available, one stack at a time) and
# stop it at the end. -p 1: one package, one stack, one test at a time
# (AGENT-PLAN §9 rule 8).

GO ?= go

.PHONY: test devstack-test devstack-hold-test

test:
	$(GO) vet ./...
	$(GO) test -p 1 ./...

# The exit tests of A2 and A3 (about 5 minutes on a running stack),
# without the hold step.
devstack-test:
	$(GO) test -p 1 -count=1 -tags devstack -timeout 60m -v ./internal/devstack/

# The hold step of A3's exit test (owner_check_required): the dev stack
# has no clock for the owner check, so it waits for a real one-hour
# deadline and takes over an hour.
devstack-hold-test:
	VETTID_DEVSTACK_HOLD=1 $(GO) test -p 1 -count=1 -tags devstack -timeout 120m -v -run '^TestExitA3Hold$$' ./internal/devstack/
