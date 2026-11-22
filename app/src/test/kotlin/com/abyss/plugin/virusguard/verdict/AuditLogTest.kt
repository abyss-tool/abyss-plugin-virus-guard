package com.abyss.plugin.virusguard.verdict

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** N-VIR-006 审计日志（追加-only / IO 兜底 / 脱敏）。 */
class AuditLogTest {

    @get:Rule
    val tmp = TemporaryFolder()

    @Test
    fun `append and tail roundtrip`() {
        val log = AuditLog(tmp.newFile("audit.log"), clock = { 1234L })
        log.append(VerdictEngine.Verdict.NOTIFY, "com.app.one", null)
        log.append(VerdictEngine.Verdict.REVIEW, "com.evil.x", "com.evil.*")
        assertEquals(2, log.count())
        assertEquals(2, log.tail().size)
        assertTrue(log.tail(1)[0].contains("REVIEW"))
        assertTrue(log.tail(1)[0].contains("com.evil.x"))
    }

    @Test
    fun `pipe chars in package name are sanitized`() {
        val log = AuditLog(tmp.newFile("a.log"), clock = { 1L })
        log.append(VerdictEngine.Verdict.NOTIFY, "com|bad|pkg", null)
        assertEquals("com_bad_pkg", log.tail()[0].split("|")[2])
    }

    @Test
    fun `io failure degrades to empty tail`() {
        // 指向目录的"文件"：追加失败被兜底，tail 空列表 —— 绝不抛出
        val log = AuditLog(tmp.newFolder("dir"), clock = { 1L })
        log.append(VerdictEngine.Verdict.NOTIFY, "x", null)
        assertEquals(0, log.count())
        assertEquals(0, log.tail().size)
    }
}
