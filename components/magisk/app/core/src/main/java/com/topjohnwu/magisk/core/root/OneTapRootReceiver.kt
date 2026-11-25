package com.topjohnwu.magisk.core.root

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class OneTapRootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION_ONE_TAP_ROOT) {
            return
        }
        context.startForegroundService(
            Intent(context, OneTapRootService::class.java)
                .setAction(ACTION_ONE_TAP_ROOT)
        )
    }

    companion object {
        const val ACTION_ONE_TAP_ROOT =
            "com.topjohnwu.magisk.action.ONE_TAP_ROOT"
    }
}
