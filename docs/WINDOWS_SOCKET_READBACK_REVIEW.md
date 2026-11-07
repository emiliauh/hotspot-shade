# Windows socket interface readback review

The proposed Windows physical adapter proof must not decode the IPv4
`IP_UNICAST_IF` readback as network byte order. Microsoft specifies network
byte order for the value passed to `setsockopt`, but host byte order for the
value returned by `getsockopt`. For `IPV6_UNICAST_IF`, both operations use
host byte order. See Microsoft's [IPv4 socket options](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options)
and [IPv6 socket options](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ipv6-socket-options).

An earlier integration design proposed decoding the IPv4 readback with
`from_be_bytes`. On little-endian Windows that would interpret a valid
host-order index such as 17 as a different value. The existing Windows native
test reads index 1 with `get_int`, which uses host order. That test checks the
documented readback; index 1 is not byte-order symmetric on a little-endian
machine. The separate write-value test checks the two write encodings.

`normalization_windows.rs` currently reads back TTL and checks the returned
integer length, but does not audit the interface option on every production
socket. Any future interface readback should decode both option values in host
order, reject an error or mismatch, and close the socket. Test that behavior
on Windows with an available non-loopback index as well as loopback. A matching socket option is
not evidence that a packet actually left through that interface. Adapter
identity and route observations remain separate, point-in-time evidence.

This review does not enable Windows direct mode or source device token use.
It records API documentation and current test scope; it is not a new Windows
host, packet, adapter, or hotspot test.
