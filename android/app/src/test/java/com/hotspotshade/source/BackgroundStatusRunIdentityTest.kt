package com.hotspotshade.source

import java.net.InetAddress
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The process run identity that the background status host fences against.
 *
 * A new live run gets a new value even when it reuses the address and port.
 * A repeated report for the same run keeps its value. These are JVM tests; they
 * create no route, TUN device, or hotspot interface.
 */
class BackgroundStatusRunIdentityTest {
    private val host = InetAddress.getByName("192.0.2.10")

    @Before
    fun setUp() {
        SourceProxyRuntime.resetObservation()
    }

    @After
    fun tearDown() {
        SourceProxyRuntime.resetObservation()
    }

    @Test
    fun aNewLiveRunGetsANewIdentityAtTheSameAddressAndPort() {
        SourceProxyRuntime.record(
            SourceProxySnapshot(SourceProxyState.RUNNING, SourceProxyStopReason.NONE, 23456),
            host,
        )
        val first = SourceProxyRuntime.binding()
        assertTrue(first.runId > 0)
        assertEquals(23456, first.port)
        assertEquals(host, first.address)

        SourceProxyRuntime.record(
            SourceProxySnapshot(SourceProxyState.STOPPED, SourceProxyStopReason.USER_STOP, 0),
        )
        SourceProxyRuntime.record(
            SourceProxySnapshot(SourceProxyState.RUNNING, SourceProxyStopReason.NONE, 23456),
            host,
        )
        val second = SourceProxyRuntime.binding()

        assertTrue(second.runId > 0)
        assertNotEquals(first.runId, second.runId)
    }

    @Test
    fun repeatedReportsForOneRunKeepTheSameIdentity() {
        val waiting = SourceProxySnapshot(
            SourceProxyState.WAITING_FOR_NETWORK,
            SourceProxyStopReason.NONE,
            0,
        )
        SourceProxyRuntime.record(waiting, host)
        val waitingId = SourceProxyRuntime.binding().runId

        SourceProxyRuntime.record(
            SourceProxySnapshot(SourceProxyState.RUNNING, SourceProxyStopReason.NONE, 23456),
            host,
        )
        val runningId = SourceProxyRuntime.binding().runId

        assertEquals(waitingId, runningId)
        assertTrue(runningId > 0)
    }

    @Test
    fun aStoppedReportHasNoRunIdentity() {
        SourceProxyRuntime.record(
            SourceProxySnapshot(SourceProxyState.STOPPED, SourceProxyStopReason.USER_STOP, 0),
        )

        assertEquals(0L, SourceProxyRuntime.binding().runId)
    }
}
