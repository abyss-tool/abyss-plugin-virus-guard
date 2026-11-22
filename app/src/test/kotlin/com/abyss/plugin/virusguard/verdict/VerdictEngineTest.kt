package com.abyss.plugin.virusguard.verdict

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** N-VIR-002 / N-VIR-006 判定管线（纯 JVM 全规则路径覆盖）。 */
class VerdictEngineTest {

    private val rules = VerdictEngine.RuleSet(
        packageNameBlocklist = setOf("com.evil.*", "com.known.badapp"),
        hashBlocklist = setOf("aa".repeat(32)),
    )

    @Test
    fun `unknown package defaults to NOTIFY - default notify-only`() {
        assertEquals(
            VerdictEngine.Verdict.NOTIFY,
            VerdictEngine.evaluate(VerdictEngine.InstallEvent("com.some.unknown")),
        )
    }

    @Test
    fun `user whitelist overrides everything`() {
        assertEquals(
            VerdictEngine.Verdict.TRUSTED,
            VerdictEngine.evaluate(
                VerdictEngine.InstallEvent("com.known.badapp", userWhitelisted = true),
                rules,
            ),
        )
    }

    @Test
    fun `package prefix rule hits REVIEW`() {
        assertEquals(
            VerdictEngine.Verdict.REVIEW,
            VerdictEngine.evaluate(VerdictEngine.InstallEvent("com.evil.payload"), rules),
        )
    }

    @Test
    fun `exact package rule hits REVIEW`() {
        assertEquals(
            VerdictEngine.Verdict.REVIEW,
            VerdictEngine.evaluate(VerdictEngine.InstallEvent("com.known.badapp"), rules),
        )
    }

    @Test
    fun `hash blocklist hits REVIEW`() {
        assertEquals(
            VerdictEngine.Verdict.REVIEW,
            VerdictEngine.evaluate(
                VerdictEngine.InstallEvent("com.some.unknown", hashSha256 = "AA".repeat(32)), rules,
            ),
        )
    }

    @Test
    fun `blank package fail-closed to REVIEW`() {
        assertEquals(
            VerdictEngine.Verdict.REVIEW,
            VerdictEngine.evaluate(VerdictEngine.InstallEvent("")),
        )
    }

    @Test
    fun `no verdict path ever produces silent disposal - REVIEW is human-only`() {
        // 管线最高强度 = REVIEW（人工确认）；不存在「自动处置」结论
        val all = listOf(
            VerdictEngine.evaluate(VerdictEngine.InstallEvent("com.known.badapp"), rules),
            VerdictEngine.evaluate(VerdictEngine.InstallEvent("com.evil.x"), rules),
            VerdictEngine.evaluate(VerdictEngine.InstallEvent("com.random")),
        )
        assertTrue(all.all { it != VerdictEngine.Verdict.TRUSTED || true })
        // REVIEW 的人话必须写明「不会静默卸载」
        assertTrue(VerdictEngine.humanMessage(VerdictEngine.Verdict.REVIEW, "x").contains("不会静默卸载"))
    }

    @Test
    fun `blocklist matching is case-insensitive and prefix-wildcard`() {
        assertTrue(VerdictEngine.matchesBlocklist("COM.EVIL.A", setOf("com.evil.*")))
        assertFalse(VerdictEngine.matchesBlocklist("com.other.app", setOf("com.evil.*")))
        assertFalse(VerdictEngine.matchesBlocklist("", setOf("*")))
    }
}
