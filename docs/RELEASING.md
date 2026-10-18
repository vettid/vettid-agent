# Releasing vettid-agent

How a release is built, signed and published, and how anyone checks it
(AGENT-PLAN §2 AG4, §6 A5). The owner does the signing, on their own
machine; the steps are scripted so that a release is one command after
the tag is pushed.

**No third party holds a VettID signing key.** The release key is on
the owner's YubiKey (an offline file key is the fallback);
the Developer ID certificate and the notarization credentials live in the
owner's Mac's login keychain. Nothing in GitHub Actions signs anything,
and no secret for signing is stored in GitHub. There is no cloud signing
and no Sigstore keyless signing.

## The files of a release

| File | What it is | Checked by |
|---|---|---|
| `vettid-agent-<version>-linux-amd64`, `-linux-arm64`, `-windows-amd64.exe` | static `CGO_ENABLED=0` binaries from `scripts/build-release` | rebuilt byte for byte (`scripts/verify-reproducible`); listed in `SHA256SUMS` |
| `vettid-agent-<version>-darwin-arm64.zip` | `vettid-agent.app` (cgo, Apple silicon), signed with the owner's Developer ID, notarized and stapled | `codesign`, Gatekeeper (`spctl`); listed in `SHA256SUMS`; **not reproducible** |
| `SHA256SUMS` | the release list | `SHA256SUMS.sig` |
| `SHA256SUMS.sig` | the owner's signature over `SHA256SUMS` | `release/allowed_signers` (and the key on vettid.org) |

`SHA256SUMS` is:

```
# vettid-agent-release/v0.2.0/<40-hex commit>
<sha256>  vettid-agent-v0.2.0-darwin-arm64.zip
<sha256>  vettid-agent-v0.2.0-linux-amd64
<sha256>  vettid-agent-v0.2.0-linux-arm64
<sha256>  vettid-agent-v0.2.0-windows-amd64.exe
```

The first line binds the signature to the tag and its commit; it is the
same stamp the binaries carry (`vettid-agent version` prints it). The
other lines are `sha256sum` lines sorted by name; `sha256sum -c` skips
the `#` line. Every file name carries the version.

`SHA256SUMS.sig` is an OpenSSH signature (`ssh-keygen -Y sign`, the
SSHSIG format) in the namespace `vettid-agent-release`. The format names
the key's algorithm (`ssh-ed25519`, or `sk-ssh-ed25519@openssh.com` for
a security key) and the hash (SHA-512): the algorithm identifier that
AG4 asks for. The namespace keeps a release signature from being taken
for a git signature (namespace `git`) or a file signature, and the other
way round. PQC-MIGRATION §4 row 5 names SLH-DSA-128s for this root in
its phase 2; that will be a new signature format and a new key, announced
on vettid.org and added to `release/allowed_signers`, not a change to
this one.

The macOS app is not reproducible: cgo brings in the Mac's C toolchain
and macOS SDK. It is checked by its Developer ID signature, Apple's
notarization and its line in the signed `SHA256SUMS`;
`scripts/verify-reproducible` leaves that line out and says so. Windows
binaries are not Authenticode-signed: the owner deferred Windows signing
(2026-10-18) until the VettID business entity exists; until then the
Windows binary is the reproducible, unsigned one. When it comes, a signed
Windows binary changes bytes and gets its own line, tied to the
reproducible original by removing the signature and comparing.

## One-time setup (the owner)

### 1. The release key: a YubiKey

The release key lives on a YubiKey (owner decision, 2026-10-18): an
`ed25519-sk` key, resident, with user verification. The private key
never leaves the YubiKey, and each signature needs the YubiKey's FIDO2
PIN and a touch. Set the FIDO2 PIN first if the YubiKey has none (`ykman
fido access change-pin`), then:

```sh
ssh-keygen -t ed25519-sk -O resident -O verify-required \
  -O application=ssh:vettid-release -C vettid-release \
  -f ~/.ssh/vettid-release
```

This writes `~/.ssh/vettid-release`, a handle that is useless without
the YubiKey, and `~/.ssh/vettid-release.pub`. `-O resident` keeps the
handle on the YubiKey too, so on another machine `ssh-keygen -K` (in an
empty directory) writes it out again. Make a second key the same way on
a spare YubiKey kept elsewhere, and list both in
`release/allowed_signers`: losing one YubiKey then loses nothing.

`scripts/sign-release -k ~/.ssh/vettid-release` takes the handle file
and expects the public key next to it as `~/.ssh/vettid-release.pub`.

**Fallback: an offline file key.** If a YubiKey cannot be used, an
ordinary Ed25519 file key works the same way with `-k`: kept on
removable media that stays offline, with a strong passphrase, and
plugged in only to sign. It is weaker (the key exists as a file, and
any machine it is plugged into can copy it), so use it only as a
fallback:

```sh
ssh-keygen -t ed25519 -C vettid-release -f /Volumes/RELEASE-KEY/vettid-release
```

### 2. Publish the public key

Add one line to [release/allowed_signers](../release/allowed_signers)
(per key), merge it to `main` **before** tagging, and publish the same
key and its fingerprint on vettid.org (AGENT-PLAN §7.4):

```sh
printf 'vettid-release namespaces="git,vettid-agent-release" %s\n' \
  "$(cut -d' ' -f1,2 ~/.ssh/vettid-release.pub)" >>release/allowed_signers
ssh-keygen -l -f ~/.ssh/vettid-release.pub      # the fingerprint for vettid.org
```

Until the file holds a key line, `scripts/sign-release` and
`scripts/verify-release` refuse to run, and the workflow's check of a
published release fails.

### 3. Signed tags

Release tags are signed with an SSH key from `release/allowed_signers`
(namespace `git`), and that key can live on the YubiKey as well: the
release key itself (the suggested allowed signers line allows both the
`git` and `vettid-agent-release` namespaces), or a separate tag-signing
`ed25519-sk` key made as in step 1 with its own line (namespaces="git"
only). Either way each tag signature asks for the PIN and a touch.

Add that key's `.pub` to the owner's GitHub account as a **signing key**
(Settings, SSH and GPG keys, New SSH key, key type "Signing Key"), so
that GitHub shows release tags as verified; the tagger email must be a
verified email of that account. Then, in the vettid-agent checkout:

```sh
git config gpg.format ssh
git config user.signingkey ~/.ssh/vettid-release   # or the tag-signing key's handle file
git config gpg.ssh.allowedSignersFile "$(pwd)/release/allowed_signers"
git config tag.gpgSign true
```

### 4. Apple (on the Mac that builds the macOS app)

- The **Team ID**: developer.apple.com, Account, Membership details. It
  is not in the repository; give it as `--team-id` or `APPLE_TEAM_ID`.
- A **Developer ID Application** certificate in the login keychain
  (Xcode, Settings, Accounts, Manage Certificates, "+", Developer ID
  Application). `security find-identity -v -p codesigning` lists it as
  `Developer ID Application: <name> (<TEAMID>)`.
- An **App ID** for the bundle identifier `org.vettid.agent`
  (developer.apple.com, Certificates, Identifiers and Profiles,
  Identifiers, "+", App IDs, explicit bundle ID). The Keychain protector
  needs the access group `<TEAMID>.org.vettid.agent`, which Developer ID
  profiles normally allow (`keychain-access-groups` `<TEAMID>.*`);
  `scripts/build-macos-app` checks the profile and says if it does not.
- A **Developer ID provisioning profile** for that App ID (Profiles, "+",
  Distribution, Developer ID, App ID `org.vettid.agent`, the certificate
  above). Download it and keep its path; give it as `--profile` or
  `APPLE_PROVISIONING_PROFILE`. It expires: make a new one when
  `build-macos-app` says so.
- **Notarization credentials** in the login keychain, saved once under
  the profile name `vettid-notary` (`--notary-profile` or `NOTARY_PROFILE`
  to use another name), with an app-specific password from
  account.apple.com:

  ```sh
  xcrun notarytool store-credentials vettid-notary \
    --apple-id <your Apple Account email> --team-id <TEAMID>
  ```

### 5. Optional: immutable releases

GitHub's release immutability (repository Settings, Releases) locks a
release's assets and tag once it is published. `sign-release` uploads
and checks everything before publishing, so it works with it; but a
published release can then no longer be turned back into a draft to fix
it, only replaced by a new version.

## Each release (the owner)

1. Merge what goes into the release to `main`, then tag and push:

   ```sh
   git switch main && git pull --ff-only
   git tag -s v0.2.0 -m "vettid-agent v0.2.0"
   git push origin v0.2.0
   ```

2. Wait for the release workflow's draft (about 10 minutes):

   ```sh
   gh run watch "$(gh run list --workflow release.yml --branch v0.2.0 --limit 1 --json databaseId --jq '.[0].databaseId')"
   ```

3. On the Mac, sign and publish:

   ```sh
   export APPLE_TEAM_ID=<TEAMID> APPLE_PROVISIONING_PROFILE=~/path/to/vettid-agent.provisionprofile
   scripts/sign-release -k ~/.ssh/vettid-release v0.2.0
   ```

   It asks for the security key's PIN and a touch once, for the
   signature over `SHA256SUMS`; it takes a few minutes to rebuild and
   to notarize, shows what it is about to publish, and asks you to type
   the tag. `--yes` skips the question. On Linux, `--no-macos` publishes
   the release without the macOS app.

4. The release workflow's `signature` job checks the published release;
   it should be green.

`sign-release`'s checks, in order: the key is in `allowed_signers`; the
tag is annotated, verifies against `allowed_signers` and is verified on
GitHub; the release is a draft made by the release workflow's successful
run for that tag and commit, with only the expected assets; the draft's
binaries match its `SHA256SUMS` and a fresh rebuild on this machine
(`scripts/verify-reproducible -m`); then the macOS app is built
(`scripts/build-macos-app`), notarized (`xcrun notarytool submit
--wait`), stapled and checked with Gatekeeper; `SHA256SUMS` is written
and signed and checked with `scripts/verify-release -A`; the files are
uploaded, downloaded again and checked again; only then is the release
published. The rebuild runs the tag's own build script as you (it is
your tag).

If anything fails, fix it and run the same command again: nothing is
published before the last step, and each run starts again from the
draft. If a release was published without a valid signature, make it a
draft again (`gh release edit v0.2.0 --draft`) and run `sign-release`
again.

## Checking a release (anyone)

```sh
git clone https://github.com/vettid/vettid-agent && cd vettid-agent
scripts/verify-release v0.2.0 vettid-agent-v0.2.0-linux-amd64
```

Compare the key fingerprint it prints with the one on vettid.org. The
same by hand, and the rebuild:

```sh
ssh-keygen -Y verify -f release/allowed_signers -I vettid-release \
  -n vettid-agent-release -s SHA256SUMS.sig <SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS                          # Linux
grep -v '^#' SHA256SUMS | shasum -a 256 -c --ignore-missing       # macOS
scripts/verify-reproducible v0.2.0 SHA256SUMS
```

On a Mac, `verify-release` also unpacks the macOS zip and checks the app
with `codesign --verify --strict` and `spctl --assess`; by hand:

```sh
ditto -x -k vettid-agent-v0.2.0-darwin-arm64.zip .
spctl --assess --type execute --verbose=2 vettid-agent.app
codesign -d --verbose=2 vettid-agent.app      # TeamIdentifier: the owner's team
```

## Changing the release key

Add the new key's line to `release/allowed_signers` and to vettid.org,
then sign with it. A retired key's line stays while older releases need
checking (the signature format has no signing time, so a line cannot be
limited to earlier signatures). A key that may be compromised is
removed from the file and from vettid.org at once, and the releases
still in use are published again as new versions signed with the new
key.
