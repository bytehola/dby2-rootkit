package com.topjohnwu.magisk.core.root

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.IBinder
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean

class OneTapRootService : Service() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val running = AtomicBoolean(false)

    override fun onCreate() {
        super.onCreate()
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "Root",
                NotificationManager.IMPORTANCE_LOW,
            )
        )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action != OneTapRootReceiver.ACTION_ONE_TAP_ROOT) {
            stopSelf(startId)
            return START_NOT_STICKY
        }

        startForeground(
            NOTIFICATION_ID,
            Notification.Builder(this, NOTIFICATION_CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_sys_download)
                .setContentTitle("DBY2 Root")
                .setContentText("Allow USB debugging on the tablet")
                .build(),
        )

        if (running.compareAndSet(false, true)) {
            serviceScope.launch {
                try {
                    OneTapRoot.acquire(
                        context = this@OneTapRootService,
                        softRebootAfterRoot = false,
                    )
                } finally {
                    running.set(false)
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
            }
        }
        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    companion object {
        private const val NOTIFICATION_CHANNEL_ID = "dby2_one_tap_root"
        private const val NOTIFICATION_ID = 0xDB2
    }
}
