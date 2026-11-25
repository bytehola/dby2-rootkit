package com.topjohnwu.magisk.ui.superuser

import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.res.stringResource
import com.topjohnwu.magisk.core.AppContext
import com.topjohnwu.magisk.core.Config
import com.topjohnwu.magisk.core.di.ServiceLocator
import com.topjohnwu.magisk.core.ktx.getLabel
import com.topjohnwu.magisk.core.model.su.SuPolicy
import com.topjohnwu.magisk.core.su.SuEvents
import com.topjohnwu.magisk.ui.component.MagiskDialog
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.topjohnwu.magisk.core.R as CoreR

@Composable
fun SuperuserRequestDialog(
    uid: Int?,
    onFinished: () -> Unit,
) {
    if (uid == null) {
        return
    }

    var appLabel by remember(uid) { mutableStateOf("[UID] $uid") }
    var packageName by remember(uid) { mutableStateOf("") }
    var deciding by remember(uid) { mutableStateOf(false) }
    val coroutineScope = rememberCoroutineScope()

    LaunchedEffect(uid) {
        withContext(Dispatchers.IO) {
            val packageManager = AppContext.packageManager
            val primaryPackage = packageManager.getPackagesForUid(uid)?.firstOrNull()
            if (primaryPackage != null) {
                packageName = primaryPackage
                runCatching {
                    packageManager.getApplicationInfo(primaryPackage, 0)
                        .getLabel(packageManager)
                }.getOrNull()?.let { appLabel = it }
            }
        }
    }

    fun decide(grantAccess: Boolean) {
        if (deciding) {
            return
        }
        deciding = true
        coroutineScope.launch {
            withContext(Dispatchers.IO) {
                val policyDao = ServiceLocator.policyDB
                val policy = policyDao.fetch(uid) ?: SuPolicy(uid)
                policy.policy = when {
                    !grantAccess -> SuPolicy.DENY
                    Config.suRestrict -> SuPolicy.RESTRICT
                    else -> SuPolicy.ALLOW
                }
                policy.logging = true
                policy.notification = true
                policyDao.update(policy)
            }
            SuEvents.notifyPolicyChanged()
            onFinished()
        }
    }

    MagiskDialog(
        onDismissRequest = { decide(false) },
        dismissOnClickOutside = false,
        dismissOnBackPress = false,
        title = stringResource(CoreR.string.su_request_title),
        confirmText = stringResource(CoreR.string.grant),
        onConfirm = { decide(true) },
        confirmEnabled = !deciding,
        dismissText = stringResource(CoreR.string.deny),
        onDismiss = { decide(false) },
    ) {
        Text(
            stringResource(
                CoreR.string.su_request_message,
                appLabel,
                packageName.ifEmpty { uid.toString() },
            ),
        )
    }
}
