package com.hotspotshade.source

import android.net.Network
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicInteger

/**
 * Send ICMP echo requests from one selected Android network.
 *
 * The socket is an unprivileged ICMP datagram socket: `AF_INET` or `AF_INET6`
 * with `SOCK_DGRAM` and `IPPROTO_ICMP` or `IPPROTO_ICMPV6`. The socket is
 * bound to the selected Network before the connect. It never uses the process
 * default network.
 *
 * The echo path has no TTL control. The kernel default applies to the outer
 * echo packet. The target device builds its inner reply with TTL 64.
 *
 * A device whose kernel or security policy refuses an ICMP datagram socket
 * returns [EchoStatus.FAILED] for every request. The app cannot detect this
 * before the first request. See `android/README.md`.
 *
 * The IPv4 checksum is set here. The IPv6 kernel computes the ICMPv6
 * checksum, as on iOS.
 */
internal class AndroidNetworkEcho(
    private val network: Network,
    private val random: SecureRandom = SecureRandom(),
) : SourceEchoSender {
    private val active = AtomicInteger()

    override fun send(target: EchoTarget, payload: ByteArray, timeoutMillis: Long): EchoResult {
        if (payload.size > SourceEchoWire.MAXIMUM_PAYLOAD) {
            return EchoResult(EchoStatus.FAILED)
        }
        if (timeoutMillis < MINIMUM_TIMEOUT_MILLIS) return EchoResult(EchoStatus.FAILED)
        if (!acquire()) return EchoResult(EchoStatus.BUSY)
        try {
            return attempt(target, payload, timeoutMillis.coerceAtMost(MAXIMUM_TIMEOUT_MILLIS))
        } finally {
            active.decrementAndGet()
        }
    }

    private fun attempt(target: EchoTarget, payload: ByteArray, timeoutMillis: Long): EchoResult {
        val ipv4 = target.family == EchoFamily.IPV4
        val domain = if (ipv4) OsConstants.AF_INET else OsConstants.AF_INET6
        val protocol = if (ipv4) OsConstants.IPPROTO_ICMP else OsConstants.IPPROTO_ICMPV6
        val fd = try {
            Os.socket(domain, OsConstants.SOCK_DGRAM, protocol)
        } catch (_: ErrnoException) {
            // A missing permission, a missing ping group, or no IPv6 stack.
            return EchoResult(EchoStatus.FAILED)
        }
        try {
            try {
                network.bindSocket(fd)
            } catch (_: Exception) {
                return EchoResult(EchoStatus.PATH_UNSATISFIED)
            }
            try {
                Os.connect(fd, target.address, 0)
            } catch (failure: ErrnoException) {
                return EchoResult(unreachable(failure))
            }
            if (!waitFor(fd, OsConstants.POLLOUT.toShort(), timeoutMillis)) {
                return EchoResult(EchoStatus.TIMEOUT)
            }
            val nonce = ByteArray(SourceEchoWire.NONCE_BYTES)
            random.nextBytes(nonce)
            val sequence = random.nextInt(1 shl 16)
            val packet = SourceEchoWire.request(target.family, payload, nonce, sequence)
            val sent = try {
                Os.write(fd, packet, 0, packet.size)
            } catch (failure: ErrnoException) {
                return EchoResult(unreachable(failure))
            }
            if (sent != packet.size) return EchoResult(EchoStatus.FAILED)
            if (!waitFor(fd, OsConstants.POLLIN.toShort(), timeoutMillis)) {
                return EchoResult(EchoStatus.TIMEOUT)
            }
            val buffer = ByteArray(MAXIMUM_REPLY_BYTES)
            val count = try {
                Os.read(fd, buffer, 0, buffer.size)
            } catch (failure: ErrnoException) {
                return EchoResult(unreachable(failure))
            }
            val reply = SourceEchoWire.validateReply(
                reply = buffer,
                count = count,
                family = target.family,
                sequence = sequence,
                nonce = nonce,
                payloadSize = payload.size,
            ) ?: return EchoResult(EchoStatus.FAILED)
            return EchoResult(EchoStatus.SUCCESS, reply)
        } finally {
            try {
                Os.close(fd)
            } catch (_: ErrnoException) {
                // The descriptor is already closed.
            }
        }
    }

    private fun acquire(): Boolean {
        while (true) {
            val current = active.get()
            if (current >= MAXIMUM_ACTIVE) return false
            if (active.compareAndSet(current, current + 1)) return true
        }
    }

    /**
     * Wait for one socket state. The call has a bounded wait on every
     * supported API level. `Os.poll` is available since API 21.
     */
    private fun waitFor(fd: java.io.FileDescriptor, events: Short, timeoutMillis: Long): Boolean {
        val entry = StructPollfd().apply {
            this.fd = fd
            this.events = events
            this.revents = 0
        }
        val ready = try {
            Os.poll(arrayOf(entry), timeoutMillis.toInt())
        } catch (_: ErrnoException) {
            return false
        }
        if (ready == 0) return false
        val revents = entry.revents.toInt()
        if (revents and (OsConstants.POLLERR or OsConstants.POLLHUP or
                OsConstants.POLLNVAL) != 0
        ) {
            return true
        }
        return revents and events.toInt() != 0
    }

    private fun unreachable(failure: ErrnoException): EchoStatus = when {
        failure.errno == OsConstants.EAGAIN -> EchoStatus.TIMEOUT
        failure.errno == OsConstants.ENETUNREACH ||
            failure.errno == OsConstants.EHOSTUNREACH ||
            failure.errno == OsConstants.ENETDOWN ||
            failure.errno == OsConstants.EADDRNOTAVAIL ->
            EchoStatus.PATH_UNSATISFIED
        else -> EchoStatus.FAILED
    }

    private companion object {
        /** The most echo attempts that can run at the same time. */
        const val MAXIMUM_ACTIVE = 8

        /** The reply buffer holds one 1200 byte payload and the headers. */
        const val MAXIMUM_REPLY_BYTES = 2048

        /** The shortest socket timeout. */
        const val MINIMUM_TIMEOUT_MILLIS = 10L

        /** The longest single echo attempt. */
        const val MAXIMUM_TIMEOUT_MILLIS = 3_000L
    }
}
