#+build linux
package relay

import "core:net"
import "core:sys/linux"

// One syscall only: send_all owns the deadline across partial writes.
send_once :: proc(sock: net.TCP_Socket, data: []byte) -> int {
	written, err := linux.send(linux.Fd(sock), data, {.NOSIGNAL})
	if err != .NONE do return -1
	return written
}
