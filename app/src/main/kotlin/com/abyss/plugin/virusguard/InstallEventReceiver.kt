package com.abyss.plugin.virusguard

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.abyss.plugin.virusguard.verdict.AuditLog
import com.abyss.plugin.virusguard.verdict.VerdictEngine

/**
 * 安装事件接收器骨架（N-VIR-001）。
 *
 * M1：只做事件归一 → 判定 → 审计，不弹任何 UI、不执行任何处置
 * （默认只提示的「提示」由处置面板/通知随 v0.2 呈现；本接收器 M1 仅
 * 记录审计流水，保证行为可回溯）。
 */
class InstallEventReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context?, intent: Intent?) {
        if (context == null || intent?.action != Intent.ACTION_PACKAGE_ADDED) return
        val pkg = intent.data?.schemeSpecificPart ?: return
        val verdict = VerdictEngine.evaluate(
            VerdictEngine.InstallEvent(packageName = pkg),
        )
        AuditLog(java.io.File(context.filesDir, "audit.log"))
            .append(verdict, pkg, matchedRule = null)
    }
}
