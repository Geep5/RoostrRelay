#+build darwin, netbsd, freebsd, openbsd
package relay

import "core:net"
import "core:sys/posix"

// One syscall only: send_all owns the deadline across partial writes.
send_once :: proc(sock: net.TCP_Socket, data: []byte) -> int {
	return int(posix.send(posix.FD(sock), raw_data(data), len(data), {.NOSIGNAL}))
}
