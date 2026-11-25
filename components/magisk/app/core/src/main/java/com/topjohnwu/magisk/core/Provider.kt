package com.topjohnwu.magisk.core

import android.os.Binder
import android.os.Bundle
import android.os.Process
import com.topjohnwu.magisk.core.base.BaseProvider
import com.topjohnwu.magisk.core.su.SuCallbackHandler
import timber.log.Timber

class Provider : BaseProvider() {

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle? {
        val callingUid = Binder.getCallingUid()
        if (callingUid != Process.ROOT_UID && callingUid != Process.myUid()) {
            Timber.w("Rejected provider call from uid=%d", callingUid)
            return null
        }
        return when (method) {
            SuCallbackHandler.LOG, SuCallbackHandler.NOTIFY -> {
                SuCallbackHandler.run(context!!, method, extras)
                Bundle.EMPTY
            }
            else -> Bundle.EMPTY
        }
    }
}
