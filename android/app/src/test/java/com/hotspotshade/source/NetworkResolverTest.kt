package com.hotspotshade.source

import java.io.IOException
import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class NetworkResolverTest {
    private val first = InetAddress.getByName("192.0.2.10")
    private val second = InetAddress.getByName("192.0.2.11")

    @Test
    fun resolveUsesTheInjectedLookupForTheRequestedHost() {
        var requested: String? = null
        val resolver = NetworkResolver { host ->
            requested = host
            arrayOf(first, second)
        }

        val result = resolver.resolve("example.test")

        assertEquals("example.test", requested)
        assertEquals(listOf(first, second), result)
    }

    @Test
    fun resolveReturnsAnEmptyListWhenTheNetworkHasNoAddress() {
        val resolver = NetworkResolver { emptyArray() }

        assertTrue(resolver.resolve("example.test").isEmpty())
    }

    @Test
    fun resolveReportsALookupFailure() {
        val resolver = NetworkResolver { throw IOException("The network is gone.") }

        try {
            resolver.resolve("example.test")
            fail("A failed lookup must throw")
        } catch (_: IOException) {
            // Expected.
        }
    }
}
