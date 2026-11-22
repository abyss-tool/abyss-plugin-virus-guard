package com.abyss.plugin.virusguard.verdict

/**
 * 纯 JVM 信任判定管线（N-VIR-002 / N-VIR-006）。
 *
 * 设计纪律（规格硬约束，全部写进判定结果而不是 UI 姿态）：
 *  - **默认只提示，绝不静默卸载**（N-VIR-006）：管线能产出的最高强度
 *    动作是 [Verdict.REVIEW]（人工确认）—— 真实「卸载 / 隔离」处置只由
 *    用户在处置面板显式触发，管线自身无处置权；
 *  - **白名单 + 人工确认双轨**（N-VIR-006）：用户白名单（信任的用户决策）
 *    优先于任何规则；规则命中的可疑项永远回落到 [Verdict.REVIEW] 等人工；
 *  - **云查询默认关闭、只传哈希**（N-VIR-004 边界，管线层面预留输入位但
 *    M1 恒为 null）—— 判定只依赖本地信号，不外传任何内容；
 *  - **误杀防护**：未知包名 = [Verdict.NOTIFY]（提示级），只有本地规则
 *    明确命中（哈希黑名单 / 包名规则）才升级 [Verdict.REVIEW]；
 *    没有任何「未证据即拦截」路径。
 *
 * 纯 JVM 可单测；Android 安装事件（PACKAGE_ADDED / install-session）在
 * [InstallEvent] 模型上归一后进入管线。
 */
object VerdictEngine {

    /** 判定结论（强度递增）。M1 管线最高只产出 [REVIEW]，永不产出处置。 */
    enum class Verdict { TRUSTED, NOTIFY, REVIEW }

    /**
     * 一次安装/已装事件的归一化输入。
     *  - [packageName] 目标包名；
     *  - [installerPackage] 安装来源（Play / 系统安装器 / 侧载来源包名，未知 null）；
     *  - [hashSha256] 安装包摘要（本地计算；M1 云查询关闭，仅本地比对）；
     *  - [userWhitelisted] 用户显式信任（白名单双轨的用户侧）。
     */
    data class InstallEvent(
        val packageName: String,
        val installerPackage: String? = null,
        val hashSha256: String? = null,
        val userWhitelisted: Boolean = false,
    )

    /** 本地判定规则集（M1：包名规则 + 哈希黑名单占位；ClamAV 签名库随 N-VIR-003）。 */
    data class RuleSet(
        /** 已知恶意/高危包名规则（小写精确或前缀通配 `de.*`）。 */
        val packageNameBlocklist: Set<String> = emptySet(),
        /** 哈希黑名单（64 位 hex 小写）。 */
        val hashBlocklist: Set<String> = emptySet(),
    ) {
        companion object {
            /** M1 内置最小规则集（占位种子；真实数据走补丁通道 abyss-patch-v1）。 */
            val EMPTY = RuleSet()
        }
    }

    /**
     * 判定入口（纯函数）。决策顺序即优先级：
     *  1. 用户白名单 → TRUSTED（用户决策最高优先，误杀防护第一道）；
     *  2. 本地黑名单明确命中 → REVIEW（人工确认，绝不静默处置）；
     *  3. 其余 → NOTIFY（默认只提示：未知即提示级，不拦截不标注恶意）。
     */
    fun evaluate(event: InstallEvent, rules: RuleSet = RuleSet.EMPTY): Verdict {
        if (event.packageName.isBlank()) {
            // 非法输入 fail-closed：提示级人工复核（绝不当作 TRUSTED）
            return Verdict.REVIEW
        }
        if (event.userWhitelisted) return Verdict.TRUSTED
        if (matchesBlocklist(event.packageName, rules.packageNameBlocklist)) {
            return Verdict.REVIEW
        }
        val hash = event.hashSha256?.lowercase()
        if (hash != null && hash in rules.hashBlocklist) return Verdict.REVIEW
        return Verdict.NOTIFY
    }

    /** 包名规则匹配（小写归一；`*` 前缀通配，其余精确）。 */
    fun matchesBlocklist(packageName: String, blocklist: Set<String>): Boolean {
        val pkg = packageName.trim().lowercase()
        if (pkg.isEmpty()) return false
        return blocklist.any { rule ->
            val r = rule.trim().lowercase()
            when {
                r.endsWith("*") -> pkg.startsWith(r.removeSuffix("*"))
                else -> pkg == r
            }
        }
    }

    /** 判定结果的人话文案（通知条 / 处置面板共用，含审计动作说明）。 */
    fun humanMessage(verdict: Verdict, packageName: String): String = when (verdict) {
        Verdict.TRUSTED -> "「$packageName」在您的信任名单中 —— 不提示"
        Verdict.NOTIFY -> "「$packageName」已安装。本插件默认只提示不拦截；如需评估可在处置面板发起人工检查"
        Verdict.REVIEW ->
            "「$packageName」命中本地规则 —— 建议人工确认。本插件不会静默卸载或隔离任何应用；处置（卸载引导 / 白名单）只能由您在处置面板显式执行"
    }
}
