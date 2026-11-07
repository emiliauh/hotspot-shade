package com.hotspotshade.source

import android.content.SharedPreferences
import com.hotspotshade.source.pairing.PairingException
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test

class TrustStoreRaceTest {
    private val keyA = ByteArray(32) { 0x11 }
    private val keyB = ByteArray(32) { 0x22 }
    private fun path() = File(Files.createTempDirectory("trust-test").toFile(), "trust")
    private fun key(bytes: ByteArray) = Base64.getEncoder().encodeToString(bytes)

    @Test fun ambiguousLegacyKeysRequireResetAndUnrelatedWritesCannotRestoreThem() {
        val prefs = FakeSharedPreferences()
        prefs.commitResult = false
        assertFalse(prefs.edit().putStringSet(KEY, mutableSetOf(key(keyA))).commit())
        prefs.commitResult = true
        prefs.edit().putInt("unrelated", 1).commit()
        val file = path()
        val store = FilePairingTrustStore(file, prefs)
        assertThrows(PairingException::class.java) { store.contains(keyA) }
        store.forgetAll()
        store.add(keyB)
        prefs.edit().putInt("port", 18080).commit()
        FilePairingTrustStore.simulateProcessRestartForTest()
        val restarted = FilePairingTrustStore(file, prefs.restart())
        assertFalse(restarted.contains(keyA))
        assertFalse(restarted.contains(keyB))
        restarted.add(keyB)
        assertTrue(restarted.contains(keyB))
    }

    @Test fun completedAddStillRequiresConfirmationAfterRestart() {
        val file = path()
        val prefs = FakeSharedPreferences()
        val store = FilePairingTrustStore(file, prefs)
        store.add(keyA)
        assertTrue(store.contains(keyA))
        assertEquals(TargetConfirmation.CONFIRMED, store.targets().single().confirmation)
        // A crash before the response and a delivered response have the same disk state.
        FilePairingTrustStore.simulateProcessRestartForTest()
        val restarted = FilePairingTrustStore(file, prefs)
        assertFalse(restarted.contains(keyA))
        assertEquals(TargetConfirmation.REQUIRED, restarted.targets().single().confirmation)
        restarted.add(keyA)
        assertTrue(restarted.contains(keyA))
        assertEquals(TargetConfirmation.CONFIRMED, restarted.targets().single().confirmation)
    }

    @Test fun trustChangesLogAddConfirmAndRemoveWithoutNamingTheKey() {
        ActivityLog.shared.clear()
        try {
            val store = FilePairingTrustStore(path(), FakeSharedPreferences())

            store.add(keyA)
            store.add(keyA)
            store.remove(keyA)
            store.remove(keyA)

            assertEquals(
                listOf(
                    ActivityEvent.TARGET_REMOVED,
                    ActivityEvent.TARGET_CONFIRMED,
                    ActivityEvent.TARGET_ADDED,
                ),
                ActivityLog.shared.entries().map { it.event },
            )
        } finally {
            ActivityLog.shared.clear()
        }
    }

    @Test fun aFailedTrustWriteLogsNothing() {
        ActivityLog.shared.clear()
        try {
            val file = path()
            val prefs = FakeSharedPreferences()
            FilePairingTrustStore(file, prefs).count
            val disk = FileTrustDisk { point -> if (point == "before-delete") throw IOException("injected") }
            val store = FilePairingTrustStore(file, prefs, disk)

            assertTrue(runCatching { store.add(keyA) }.isFailure)

            assertTrue(ActivityLog.shared.entries().isEmpty())
        } finally {
            ActivityLog.shared.clear()
        }
    }

    @Test fun targetSnapshotTracksChangesFromAnotherStoreInstance() {
        val file = path()
        val prefs = FakeSharedPreferences()
        val settings = FilePairingTrustStore(file, prefs)
        val listener = FilePairingTrustStore(file, prefs)
        listener.add(keyA)
        listener.add(keyB)
        FilePairingTrustStore.simulateProcessRestartForTest()
        listener.add(keyA)
        val statuses = settings.targets().associate { it.id to it.confirmation }
        assertEquals(TargetConfirmation.CONFIRMED, statuses[key(keyA)])
        assertEquals(TargetConfirmation.REQUIRED, statuses[key(keyB)])
        listener.remove(keyA)
        assertEquals(listOf(key(keyB)), settings.targets().map { it.id })
    }
    
    @Test fun interruptedAddNeverActivatesOnRestart() {
        for (phase in listOf("before-delete", "after-delete", "before-directory-sync", "after-directory-sync")) {
            for (occurrence in 1..4) {
                val file = path()
                val prefs = FakeSharedPreferences()
                FilePairingTrustStore(file, prefs).count
                var seen = 0
                val disk = FileTrustDisk { point ->
                    if (point == phase && ++seen == occurrence) throw IOException("injected")
                }
                val store = FilePairingTrustStore(file, prefs, disk)
                if (runCatching { store.add(keyA) }.isSuccess) continue
                assertThrows(PairingException::class.java) { store.contains(keyA) }
                FilePairingTrustStore.simulateProcessRestartForTest()
                val restarted = FilePairingTrustStore(file, prefs)
                if (RealTrustDisk.exists(File(file.path + ".intent"))) {
                    assertThrows(PairingException::class.java) { restarted.contains(keyA) }
                } else {
                    assertFalse("$phase occurrence $occurrence", restarted.contains(keyA))
                }
            }
        }
    }
    
    @Test fun previousFileFormatRequiresConfirmationAndLegacyRemainsForDowngrade() {
        val file = path()
        val prefs = FakeSharedPreferences()
        prefs.edit().putStringSet(KEY, mutableSetOf(key(keyB))).commit()
        File(file.path + ".migrated").writeText("marker")
        file.writeText("hotspotshade-trust-v1\n${key(keyA)}\n")
        FilePairingTrustStore.simulateProcessRestartForTest()
        val store = FilePairingTrustStore(file, prefs)
        assertFalse(store.contains(keyA))
        assertFalse(store.contains(keyB))
        store.add(keyA)
        assertTrue(store.contains(keyA))
        assertTrue(prefs.getStringSet(KEY, null)!!.contains(key(keyB)))
    }
    
    @Test fun legacyIntentAndInvalidKeysFailClosedUntilReset() {
        for (intent in listOf(true, false)) {
            val prefs = FakeSharedPreferences()
            if (intent) prefs.edit().putString("paired-targets-write-intent", "pending").commit()
            else prefs.edit().putStringSet(KEY, mutableSetOf("invalid")).commit()
            val store = FilePairingTrustStore(path(), prefs)
            assertThrows(PairingException::class.java) { store.count }
            store.forgetAll()
            assertEquals(0, store.count)
        }
    }

    @Test fun faultsAtEveryTransactionBoundaryBlockAndReset() {
        // Before and after each durable operation, including the intent removal.
        for (step in 1..8) for (after in listOf(false, true)) {
            val file = path()
            val prefs = FakeSharedPreferences()
            FilePairingTrustStore(file, prefs).add(keyA)
            val disk = FaultDisk(step, after)
            val store = FilePairingTrustStore(file, prefs, disk)
            val failed = runCatching { store.forget(key(keyA)) }.isFailure
            if (!failed) continue
            assertThrows(PairingException::class.java) { store.contains(keyA) }
            FilePairingTrustStore.simulateProcessRestartForTest()
            val restarted = FilePairingTrustStore(file, prefs)
            // Before the first durable intent, old trust can survive a restart.
            // After durable intent deletion, the replacement may already be committed.
            if (RealTrustDisk.exists(File(file.path + ".intent"))) {
                assertThrows(PairingException::class.java) { restarted.contains(keyA) }
            }
            restarted.forgetAll()
            FilePairingTrustStore.simulateProcessRestartForTest()
            assertFalse(FilePairingTrustStore(file, prefs).contains(keyA))
        }
    }

    @Test fun corruptOrMissingMigratedDataNeverFallsBackToLegacy() {
        val prefs = FakeSharedPreferences()
        prefs.edit().putStringSet(KEY, mutableSetOf(key(keyA))).commit()
        val file = path()
        val store = FilePairingTrustStore(file, prefs)
        assertThrows(PairingException::class.java) { store.contains(keyA) }
        store.forgetAll()
        store.add(keyA)
        file.writeText("bad")
        assertThrows(PairingException::class.java) { store.contains(keyA) }
        file.delete()
        assertThrows(PairingException::class.java) { store.contains(keyA) }
        store.forgetAll()
        assertFalse(store.contains(keyA))
    }

    @Test fun actualFileWriteAndSyncFailuresLeaveEitherIntentOrDurableReplacement() {
        val phases = listOf("before-write", "after-write", "after-file-sync", "before-rename", "after-rename", "before-directory-sync", "after-directory-sync", "before-delete", "after-delete")
        for (phase in phases) for (occurrence in 1..4) {
            val file = path()
            val prefs = FakeSharedPreferences()
            FilePairingTrustStore(file, prefs).add(keyA)
            var seen = 0
            val disk = FileTrustDisk { point ->
                if (point == phase && ++seen == occurrence) throw IOException("injected")
            }
            val store = FilePairingTrustStore(file, prefs, disk)
            if (runCatching { store.forget(key(keyA)) }.isSuccess) continue
            assertThrows(PairingException::class.java) { store.contains(keyA) }
            FilePairingTrustStore.simulateProcessRestartForTest()
            val restarted = FilePairingTrustStore(file, prefs)
            if (RealTrustDisk.exists(File(file.path + ".intent"))) {
                assertThrows(PairingException::class.java) { restarted.contains(keyA) }
            }
            restarted.forgetAll()
            assertFalse(restarted.contains(keyA))
        }
    }

    @Test fun twoInstancesSerializeMutations() {
        val prefs = FakeSharedPreferences()
        val file = path()
        val first = FilePairingTrustStore(file, prefs)
        first.add(keyA)
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val disk = object : TrustDisk by RealTrustDisk {
            override fun write(file: File, bytes: ByteArray) {
                if (file.name.endsWith(".intent")) { entered.countDown(); release.await(5, TimeUnit.SECONDS) }
                RealTrustDisk.write(file, bytes)
            }
        }
        val adding = Thread { FilePairingTrustStore(file, prefs, disk).add(keyB) }
        adding.start()
        assertTrue(entered.await(5, TimeUnit.SECONDS))
        val clearing = Thread { FilePairingTrustStore(file, prefs).forgetAll() }
        clearing.start()
        release.countDown()
        adding.join(5000); clearing.join(5000)
        assertFalse(adding.isAlive); assertFalse(clearing.isAlive)
        assertEquals(0, first.count)
    }

    private class FaultDisk(private val failAt: Int, private val after: Boolean) : TrustDisk by RealTrustDisk {
        private var operation = 0
        private fun perform(block: () -> Unit) {
            operation++
            if (operation == failAt && !after) throw IOException("before")
            block()
            if (operation == failAt && after) throw IOException("after")
        }
        override fun write(file: File, bytes: ByteArray) = perform { RealTrustDisk.write(file, bytes) }
        override fun delete(file: File) = perform { RealTrustDisk.delete(file) }
    }
    private class FakeSharedPreferences : SharedPreferences {
        private val values = mutableMapOf<String, Any>()
        private var disk = mutableMapOf<String, Any>()
        var commitResult = true
        fun restart() = FakeSharedPreferences().also { it.values.putAll(disk); it.disk.putAll(disk) }
        override fun getAll(): MutableMap<String, *> = values.toMutableMap()
        override fun getString(key: String?, defValue: String?): String? = values[key] as? String ?: defValue
        override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? {
            @Suppress("UNCHECKED_CAST")
            return (values[key] as? Set<String>)?.toMutableSet() ?: defValues
        }
        override fun getInt(key: String?, defValue: Int) = values[key] as? Int ?: defValue
        override fun getLong(key: String?, defValue: Long) = values[key] as? Long ?: defValue
        override fun getFloat(key: String?, defValue: Float) = values[key] as? Float ?: defValue
        override fun getBoolean(key: String?, defValue: Boolean) = values[key] as? Boolean ?: defValue
        override fun contains(key: String?) = values.containsKey(key)
        override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) = Unit
        override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) = Unit
        override fun edit(): SharedPreferences.Editor = object : SharedPreferences.Editor {
            override fun putString(key: String?, value: String?) = apply { values[key!!] = value!! }
            override fun putStringSet(key: String?, value: MutableSet<String>?) = apply { values[key!!] = value!!.toSet() }
            override fun putInt(key: String?, value: Int) = apply { values[key!!] = value }
            override fun putLong(key: String?, value: Long) = apply { values[key!!] = value }
            override fun putFloat(key: String?, value: Float) = apply { values[key!!] = value }
            override fun putBoolean(key: String?, value: Boolean) = apply { values[key!!] = value }
            override fun remove(key: String?) = apply { values.remove(key) }
            override fun clear() = apply { values.clear() }
            override fun commit(): Boolean {
                if (commitResult) disk = values.toMutableMap()
                return commitResult
            }
            override fun apply() = Unit
        }
    }
    private companion object { const val KEY = "paired-targets" }
}
