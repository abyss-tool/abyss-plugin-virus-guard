package com.abyss.plugin.virusguard.verdict

import java.io.File

/**
 * 追加式审计日志（N-VIR-006：审计日志，只落本地、不外传）。
 *
 * 纪律：
 *  - 追加-only（不改写历史，审计语义）；单行 JSON-free（纯文本脱敏格式）；
 *  - 一切 IO runCatching 静默兜底 —— 审计日志自身绝不成为新崩溃源；
 *  - 记录内容只含判定要素（包名 / verdict / 规则命中 / 时间戳），无任何
 *    内容数据；云查询关闭状态下不存在外传面。
 */
class AuditLog(private val file: File, private val clock: () -> Long = System::currentTimeMillis) {

    /** 记录一条判定；格式：`epochMs|verdict|package|matchedRule|-`。 */
    fun append(verdict: VerdictEngine.Verdict, packageName: String, matchedRule: String?) {
        val pkg = packageName.replace("|", "_").take(120)
        val rule = (matchedRule ?: "-").replace("|", "_").take(80)
        runCatching {
            file.appendText("${clock()}|${verdict.name}|$pkg|$rule|\n")
        }
    }

    /** 读回最近 n 条（处置面板「最近判定」；IO 失败返回空列表）。 */
    fun tail(n: Int = 50): List<String> = runCatching {
        file.readLines().takeLast(n)
    }.getOrDefault(emptyList())

    /** 总条数（设置页统计）。 */
    fun count(): Int = runCatching { file.readLines().size }.getOrDefault(0)
}
