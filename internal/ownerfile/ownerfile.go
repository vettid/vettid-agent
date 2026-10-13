// Package ownerfile writes and checks files that only the owning user
// may read: connection.enc, agent.token, the LEASH keypair, the NATS
// credentials file and the config directory that holds them.
//
// On POSIX this is the mode bits the agent has always used (0600 for
// files, 0700 for directories). On Windows mode bits are not an access
// control: os.WriteFile ignores them and os.FileMode.Perm() reports
// 0666 for any writable file. There the same intent is expressed with
// a protected DACL (see ownerfile_windows.go).
//
// SECURITY: Check fails closed. A file whose protection cannot be read
// or understood is reported as not owner-only.
package ownerfile
