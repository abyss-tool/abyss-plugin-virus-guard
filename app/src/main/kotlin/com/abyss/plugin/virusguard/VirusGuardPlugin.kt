package com.abyss.plugin.virusguard

/**
 * HOST_API v1 宿主入口（N-VIR-001 骨架）。
 *
 * M1 切片：信任判定管线（纯 JVM）+ 审计日志 + 安装事件归一模型；
 * BroadcastReceiver（PACKAGE_ADDED）与 install-session 监听随
 * N-VIR-001 v0.2 接线（ROM 差异会话广播 vs dumpsys 轮询降级，见规格
 * 风险清单）—— 判定管线契约先行，接收器只换实现不换语义。
 */
class VirusGuardPlugin {

    val id: String = "abyss-plugin-virus-guard"

    val minHostApi: Int = PluginContract.HOST_API_VERSION

    fun describeCapabilities(): List<String> = listOf(
        "纯 JVM 信任判定管线（默认只提示、绝不静默卸载 —— N-VIR-006）",
        "白名单 + 人工确认双轨误杀防护；审计日志只落本地",
        "安装事件拦截骨架（PACKAGE_ADDED / install-session 接线随 v0.2）",
        "ClamAV 级签名库与 VirusTotal 云查询（默认关闭、只传哈希）随 v0.3/v0.4",
    )
}
