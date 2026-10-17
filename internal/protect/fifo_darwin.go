//go:build darwin

package protect

import "syscall"

// namedFIFO: macOS reports anonymous pipes with a permissive mode and no
// link to a directory (link count 0); a named FIFO has a link.
func namedFIFO(st *syscall.Stat_t) bool { return st.Nlink > 0 }
