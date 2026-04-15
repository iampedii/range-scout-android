package com.pedrammarandi.androidscanner.scan.runtime

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.os.Build
import androidx.core.app.NotificationCompat
import com.pedrammarandi.androidscanner.MainActivity
import com.pedrammarandi.androidscanner.R

private const val channelId = "dns-scan-runtime"
private const val notificationId = 7

class ScanNotifier(
    private val context: Context,
) {
    fun ensureChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return
        }

        val manager = context.getSystemService(NotificationManager::class.java)
        val channel = NotificationChannel(
            channelId,
            context.getString(R.string.scan_notification_channel_name),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = context.getString(R.string.scan_notification_channel_description)
        }
        manager.createNotificationChannel(channel)
    }

    fun buildPreparingNotification(contentText: String = "Preparing scan runtime"): Notification {
        return buildNotification(
            contentText = contentText,
            progressCurrent = 0,
            progressTotal = 0,
            indeterminate = true,
        )
    }

    fun buildProgressNotification(scanned: Long, total: Long): Notification {
        val indeterminate = total <= 0
        val contentText = if (indeterminate) {
            "Starting scan"
        } else {
            "Scanned $scanned of $total targets"
        }
        return buildNotification(
            contentText = contentText,
            progressCurrent = scanned.coerceAtMost(Int.MAX_VALUE.toLong()).toInt(),
            progressTotal = total.coerceAtMost(Int.MAX_VALUE.toLong()).toInt(),
            indeterminate = indeterminate,
        )
    }

    fun notifyProgress(scanned: Long, total: Long) {
        notifyProgress(
            contentText = if (total <= 0) {
                "Starting scan"
            } else {
                "Scanned $scanned of $total targets"
            },
            progressCurrent = scanned,
            progressTotal = total,
        )
    }

    fun notifyProgress(
        contentText: String,
        progressCurrent: Long,
        progressTotal: Long,
    ) {
        val manager = context.getSystemService(NotificationManager::class.java)
        manager.notify(
            notificationId,
            buildNotification(
                contentText = contentText,
                progressCurrent = progressCurrent.coerceAtMost(Int.MAX_VALUE.toLong()).toInt(),
                progressTotal = progressTotal.coerceAtMost(Int.MAX_VALUE.toLong()).toInt(),
                indeterminate = progressTotal <= 0,
            ),
        )
    }

    fun foregroundId(): Int = notificationId

    private fun buildNotification(
        contentText: String,
        progressCurrent: Int,
        progressTotal: Int,
        indeterminate: Boolean,
    ): Notification {
        val launchIntent = PendingIntent.getActivity(
            context,
            0,
            android.content.Intent(context, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        return NotificationCompat.Builder(context, channelId)
            .setSmallIcon(android.R.drawable.stat_sys_download)
            .setContentTitle(context.getString(R.string.scan_notification_title))
            .setContentText(contentText)
            .setContentIntent(launchIntent)
            .setOnlyAlertOnce(true)
            .setOngoing(true)
            .setProgress(progressTotal, progressCurrent, indeterminate)
            .build()
    }
}
