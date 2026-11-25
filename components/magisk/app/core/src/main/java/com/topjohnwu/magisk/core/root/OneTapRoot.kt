package com.topjohnwu.magisk.core.root

import android.content.Context
import android.util.Base64
import com.topjohnwu.magisk.core.BuildConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException

object OneTapRoot {

    enum class Step {
        CHECKING,
        PREPARING,
        EXPLOITING,
        WAITING_FOR_ROOT,
        INSTALLING_MAGISK,
        VERIFYING,
        ACTIVATING_EXTENSIONS,
        SCHEDULING_SOFT_REBOOT,
    }

    data class Progress(
        val step: Step,
        val detail: String,
    )

    data class Result(
        val output: String,
    )

    suspend fun acquire(
        context: Context,
        softRebootAfterRoot: Boolean = false,
        onProgress: (Progress) -> Unit = {},
    ): Result = withContext(Dispatchers.IO) {
        val applicationContext = context.applicationContext
        val localAdbClient = LocalAdbClient(applicationContext)
        val capturedOutput = StringBuilder()

        fun report(step: Step, detail: String) {
            capturedOutput.append(detail).append('\n')
            onProgress(Progress(step, detail))
        }

        report(Step.CHECKING, "Checking the local ADB bridge")
        val adbIdentity = localAdbClient.shell("id")
        if (!adbIdentity.contains("uid=2000(shell)")) {
            throw IOException("Local ADB did not return the shell identity")
        }

        runCatching {
            localAdbClient.shell(
                "pm uninstall dev.dby2.dirtyfrag",
                STAGE_TIMEOUT_MILLISECONDS,
            )
        }

        stageRemoteFile(
            applicationContext,
            localAdbClient,
            "$ASSET_DIRECTORY/dfroot-su.sh",
            ROOT_BROKER_CLIENT_PATH,
        )

        val rootAlreadyAvailable = runCatching {
            localAdbClient.shell(
                "/system/bin/timeout 3 $ROOT_BROKER_CLIENT_PATH -c id",
                ROOT_PROBE_TIMEOUT_MILLISECONDS,
            )
        }.getOrNull()?.contains("uid=0(root)") == true

        if (rootAlreadyAvailable) {
            report(Step.CHECKING, "Existing UID 0 broker detected")
        } else {
            report(Step.PREPARING, "Preparing the shell-domain exploit")
            stageRemoteFile(
                applicationContext,
                localAdbClient,
                "$ASSET_DIRECTORY/ondevice-prep.sh",
                PREPARATION_SCRIPT_PATH,
            )

            val preparationCommand = "sh $PREPARATION_SCRIPT_PATH " +
                shellQuote(applicationContext.packageName)
            val preparationOutput = localAdbClient.shell(
                preparationCommand,
                PREPARATION_TIMEOUT_MILLISECONDS,
            )
            capturedOutput.append(preparationOutput).append('\n')
            if (!preparationOutput.contains("MODULE_PREP_READY")) {
                throw IOException(
                    "GhostLock module preparation failed: ${preparationOutput.trim()}",
                )
            }

            report(Step.EXPLOITING, "Starting DirtyFrag")
            val dirtyFragBinary = File(
                applicationContext.applicationInfo.nativeLibraryDir,
                DIRTYFRAG_BINARY_NAME,
            )
            if (!dirtyFragBinary.isFile) {
                throw IOException("DirtyFrag binary is missing from the APK")
            }

            val dirtyFragOutput = IpSecProcessRunner.run(
                applicationContext,
                dirtyFragBinary,
                DIRTYFRAG_TIMEOUT_MILLISECONDS,
            )
            capturedOutput.append(dirtyFragOutput.output).append('\n')

            report(Step.WAITING_FOR_ROOT, "Waiting for the UID 0 broker")
            waitForRoot(localAdbClient, capturedOutput)
        }

        report(Step.INSTALLING_MAGISK, "Installing the Magisk environment")
        val installationOutput = installMagisk(applicationContext, localAdbClient)
        capturedOutput.append(installationOutput).append('\n')
        if (!installationOutput.contains("MAGISK_READY")) {
            capturedOutput.append("Setup output ended before the completion marker\n")
        }

        report(Step.VERIFYING, "Verifying the installed Magisk environment")
        val verificationOutput = localAdbClient.shell(
            "$ROOT_BROKER_CLIENT_PATH -c " +
                shellQuote(
                    "/debug_ramdisk/magisk -v; " +
                        "/system/bin/magisk -v; " +
                        "test -x /system/bin/su; " +
                        "/system/bin/su -c id",
                ),
            VERIFICATION_TIMEOUT_MILLISECONDS,
        )
        capturedOutput.append(verificationOutput).append('\n')
        if (!verificationOutput.contains(":MAGISK:") ||
            !verificationOutput.contains("uid=0(root)")
        ) {
            throw IOException(
                "Magisk verification failed: ${verificationOutput.trim()}",
            )
        }

        report(
            Step.ACTIVATING_EXTENSIONS,
            "Installing the bundled Zygisk and Xposed modules",
        )
        val extensionInstallationOutput =
            installExtensions(applicationContext, localAdbClient)
        capturedOutput.append(extensionInstallationOutput).append('\n')
        if (!extensionInstallationOutput.contains("DBY2_EXTENSIONS_READY")) {
            throw IOException(
                "Zygisk and Xposed module installation failed: " +
                    extensionInstallationOutput.trim(),
            )
        }

        report(Step.ACTIVATING_EXTENSIONS, "Starting the Zygisk and Xposed runtime")
        val extensionOutput = activateExtensions(applicationContext, localAdbClient)
        capturedOutput.append(extensionOutput).append('\n')
        if (!extensionOutput.contains("DBY2_XPOSED_READY")) {
            throw IOException(
                "Zygisk and Xposed activation failed: ${extensionOutput.trim()}",
            )
        }

        if (softRebootAfterRoot) {
            report(
                Step.SCHEDULING_SOFT_REBOOT,
                "Scheduling the framework restart in $SOFT_REBOOT_DELAY_SECONDS seconds",
            )
            val softRebootOutput = scheduleSoftReboot(
                applicationContext,
                localAdbClient,
                SOFT_REBOOT_DELAY_SECONDS,
            )
            capturedOutput.append(softRebootOutput).append('\n')
            if (!softRebootOutput.contains("DBY2_SOFT_REBOOT_SCHEDULED")) {
                throw IOException(
                    "Framework restart scheduling failed: ${softRebootOutput.trim()}",
                )
            }
        }

        Result(capturedOutput.toString().trim())
    }

    suspend fun scheduleFrameworkRestart(
        context: Context,
        delaySeconds: Int = 1,
    ): Result = withContext(Dispatchers.IO) {
        val applicationContext = context.applicationContext
        val localAdbClient = LocalAdbClient(applicationContext)
        val output = scheduleSoftReboot(
            applicationContext,
            localAdbClient,
            delaySeconds,
        )
        if (!output.contains("DBY2_SOFT_REBOOT_SCHEDULED")) {
            throw IOException(
                "Framework restart scheduling failed: ${output.trim()}",
            )
        }
        Result(output.trim())
    }

    private fun installExtensions(
        context: Context,
        localAdbClient: LocalAdbClient,
    ): String {
        stageRemoteFile(
            context,
            localAdbClient,
            "$ASSET_DIRECTORY/install-extensions.sh",
            EXTENSION_INSTALLER_PATH,
        )
        val installerCommand = buildString {
            append("sh $EXTENSION_INSTALLER_PATH ")
            append(shellQuote(context.applicationInfo.sourceDir))
        }
        return localAdbClient.shell(
            "$ROOT_BROKER_CLIENT_PATH -c ${shellQuote(installerCommand)}",
            EXTENSION_INSTALL_TIMEOUT_MILLISECONDS,
        )
    }

    private fun activateExtensions(
        context: Context,
        localAdbClient: LocalAdbClient,
    ): String {
        val previousLogSize = localAdbClient.shell(
            "$ROOT_BROKER_CLIENT_PATH -c " +
                shellQuote(
                    "if [ -f $EXTENSION_LOG_PATH ]; " +
                        "then wc -c < $EXTENSION_LOG_PATH; " +
                        "else echo 0; fi",
                ),
            STAGE_TIMEOUT_MILLISECONDS,
        ).trim().toIntOrNull() ?: 0

        stageRemoteFile(
            context,
            localAdbClient,
            "$ASSET_DIRECTORY/activate-xposed.sh",
            EXTENSION_SCRIPT_PATH,
        )
        stageRemoteFile(
            context,
            localAdbClient,
            "$ASSET_DIRECTORY/vector-service-compat.sh",
            VECTOR_SERVICE_SCRIPT_PATH,
        )
        stageRemoteFile(
            context,
            localAdbClient,
            "$ASSET_DIRECTORY/set-usap-policy.sh",
            USAP_POLICY_SCRIPT_PATH,
        )
        val activationOutput = localAdbClient.shell(
            "$ROOT_BROKER_CLIENT_PATH -c " +
                shellQuote("sh $EXTENSION_SCRIPT_PATH"),
            EXTENSION_TIMEOUT_MILLISECONDS,
        )
        val logOutput = localAdbClient.shell(
            "$ROOT_BROKER_CLIENT_PATH -c " +
                shellQuote(
                    "if [ -f $EXTENSION_LOG_PATH ]; " +
                        "then tail -c +${previousLogSize + 1} $EXTENSION_LOG_PATH; fi",
                ),
            STAGE_TIMEOUT_MILLISECONDS,
        )
        return listOf(activationOutput.trim(), logOutput.trim())
            .filter { output -> output.isNotEmpty() }
            .joinToString("\n")
    }

    private fun scheduleSoftReboot(
        context: Context,
        localAdbClient: LocalAdbClient,
        delaySeconds: Int,
    ): String {
        stageRemoteFile(
            context,
            localAdbClient,
            "$ASSET_DIRECTORY/soft-reboot-framework.sh",
            SOFT_REBOOT_SCRIPT_PATH,
        )
        val scheduleCommand = "sh $SOFT_REBOOT_SCRIPT_PATH $delaySeconds"
        return localAdbClient.shell(
            "$ROOT_BROKER_CLIENT_PATH -c ${shellQuote(scheduleCommand)}",
            STAGE_TIMEOUT_MILLISECONDS,
        )
    }

    private fun installMagisk(
        context: Context,
        localAdbClient: LocalAdbClient,
    ): String {
        stageRemoteFile(
            context,
            localAdbClient,
            "$ASSET_DIRECTORY/setup-magisk.sh",
            SETUP_SCRIPT_PATH,
        )
        stageRemoteFile(
            context,
            localAdbClient,
            "$ASSET_DIRECTORY/magisk-wrapper.sh",
            MAGISK_WRAPPER_PATH,
        )
        stageRemoteFile(
            context,
            localAdbClient,
            "$ASSET_DIRECTORY/su-wrapper.sh",
            SU_WRAPPER_PATH,
        )
        stageRemoteFile(
            context,
            localAdbClient,
            "util_functions.sh",
            UTIL_FUNCTIONS_PATH,
        )
        stageRemoteFile(
            context,
            localAdbClient,
            "boot_patch.sh",
            BOOT_PATCH_PATH,
        )

        val setupCommand = buildString {
            append("sh $SETUP_SCRIPT_PATH ")
            append(context.applicationInfo.uid)
            append(' ')
            append(shellQuote(context.applicationInfo.nativeLibraryDir))
            append(' ')
            append(shellQuote(BuildConfig.APP_VERSION_NAME))
        }
        return localAdbClient.shell(
            "$ROOT_BROKER_CLIENT_PATH -c ${shellQuote(setupCommand)}",
            INSTALL_TIMEOUT_MILLISECONDS,
        )
    }

    private fun waitForRoot(
        localAdbClient: LocalAdbClient,
        capturedOutput: StringBuilder,
    ) {
        val deadline = System.currentTimeMillis() + ROOT_WAIT_TIMEOUT_MILLISECONDS
        var lastOutput = ""
        while (System.currentTimeMillis() < deadline) {
            lastOutput = runCatching {
                localAdbClient.shell(
                    "/system/bin/timeout 3 $ROOT_BROKER_CLIENT_PATH -c id",
                    ROOT_PROBE_TIMEOUT_MILLISECONDS,
                )
            }.getOrElse { error ->
                error.message.orEmpty()
            }
            if (lastOutput.contains("uid=0(root)")) {
                capturedOutput.append(lastOutput).append('\n')
                return
            }
            Thread.sleep(ROOT_POLL_INTERVAL_MILLISECONDS)
        }

        throw IOException("UID 0 broker did not become available: ${lastOutput.trim()}")
    }

    private fun stageRemoteFile(
        context: Context,
        localAdbClient: LocalAdbClient,
        assetName: String,
        remotePath: String,
    ) {
        val assetBytes = context.assets.open(assetName).use { input ->
            input.readBytes()
        }
        val encodedAsset = Base64.encodeToString(assetBytes, Base64.NO_WRAP)
        localAdbClient.shell(
            "echo $encodedAsset | base64 -d > $remotePath; chmod 755 $remotePath",
            STAGE_TIMEOUT_MILLISECONDS,
        )
    }

    private fun shellQuote(text: String): String {
        return "'" + text.replace("'", "'\\''") + "'"
    }

    private const val ASSET_DIRECTORY = "one_tap_root"
    private const val ROOT_BROKER_CLIENT_PATH = "/data/local/tmp/dfroot-su"
    private const val PREPARATION_SCRIPT_PATH = "/data/local/tmp/one-tap-prepare.sh"
    private const val SETUP_SCRIPT_PATH = "/data/local/tmp/one-tap-setup-magisk.sh"
    private const val MAGISK_WRAPPER_PATH = "/data/local/tmp/one-tap-magisk-wrapper.sh"
    private const val SU_WRAPPER_PATH = "/data/local/tmp/one-tap-su-wrapper.sh"
    private const val UTIL_FUNCTIONS_PATH = "/data/local/tmp/one-tap-util_functions.sh"
    private const val BOOT_PATCH_PATH = "/data/local/tmp/one-tap-boot_patch.sh"
    private const val EXTENSION_INSTALLER_PATH =
        "/data/local/tmp/one-tap-install-extensions.sh"
    private const val EXTENSION_SCRIPT_PATH = "/data/local/tmp/one-tap-activate-xposed.sh"
    private const val VECTOR_SERVICE_SCRIPT_PATH =
        "/data/local/tmp/one-tap-vector-service.sh"
    private const val USAP_POLICY_SCRIPT_PATH =
        "/data/local/tmp/one-tap-usap-policy.sh"
    private const val SOFT_REBOOT_SCRIPT_PATH =
        "/data/local/tmp/one-tap-soft-reboot-framework.sh"
    private const val EXTENSION_LOG_PATH = "/data/local/tmp/dby2-xposed-activate.log"
    private const val DIRTYFRAG_BINARY_NAME = "libdirtyfrag.so"

    private const val STAGE_TIMEOUT_MILLISECONDS = 30_000
    private const val PREPARATION_TIMEOUT_MILLISECONDS = 180_000
    private const val DIRTYFRAG_TIMEOUT_MILLISECONDS = 50_000L
    private const val ROOT_PROBE_TIMEOUT_MILLISECONDS = 8_000
    private const val ROOT_WAIT_TIMEOUT_MILLISECONDS = 60_000L
    private const val ROOT_POLL_INTERVAL_MILLISECONDS = 500L
    private const val INSTALL_TIMEOUT_MILLISECONDS = 90_000
    private const val VERIFICATION_TIMEOUT_MILLISECONDS = 20_000
    private const val EXTENSION_INSTALL_TIMEOUT_MILLISECONDS = 240_000
    private const val EXTENSION_TIMEOUT_MILLISECONDS = 120_000
    private const val SOFT_REBOOT_DELAY_SECONDS = 10
}
