package com.topjohnwu.magisk.core.root

import android.content.Context
import android.net.IpSecAlgorithm
import android.net.IpSecManager
import android.net.IpSecTransform
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.concurrent.TimeUnit

internal data class ProcessOutput(
    val exitStatus: Int,
    val output: String,
)

internal object IpSecProcessRunner {

    fun run(
        context: Context,
        binary: File,
        timeoutMilliseconds: Long,
    ): ProcessOutput {
        val ipSecManager = context.getSystemService(IpSecManager::class.java)
            ?: throw IllegalStateException("IpSecManager is unavailable")

        var encapsulationSocket: IpSecManager.UdpEncapsulationSocket? = null
        var parameterIndex: IpSecManager.SecurityParameterIndex? = null
        var transform: IpSecTransform? = null

        try {
            val loopbackAddress = InetAddress.getByName("127.0.0.1")
            val openedEncapsulationSocket = ipSecManager.openUdpEncapsulationSocket()
            encapsulationSocket = openedEncapsulationSocket
            val openedParameterIndex =
                ipSecManager.allocateSecurityParameterIndex(loopbackAddress)
            parameterIndex = openedParameterIndex

            val encryptionKey = ByteArray(32)
            SecureRandom().nextBytes(encryptionKey)

            val senderSocket = DatagramSocket()
            val senderPort = senderSocket.localPort
            senderSocket.close()

            transform = IpSecTransform.Builder(context)
                .setEncryption(IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, encryptionKey))
                .setIpv4Encapsulation(openedEncapsulationSocket, senderPort)
                .buildTransportModeTransform(loopbackAddress, openedParameterIndex)

            val command = listOf(
                binary.absolutePath,
                "--encap-port",
                openedEncapsulationSocket.port.toString(),
                "--sender-port",
                senderPort.toString(),
                "--spi",
                Integer.toUnsignedString(openedParameterIndex.spi),
                "--aes-key",
                encryptionKey.toHex(),
            )
            return runAndCapture(command, timeoutMilliseconds)
        } finally {
            transform?.close()
            parameterIndex?.close()
            encapsulationSocket?.close()
        }
    }

    private fun runAndCapture(command: List<String>, timeoutMilliseconds: Long): ProcessOutput {
        val process = ProcessBuilder(command)
            .redirectErrorStream(true)
            .start()
        val capturedOutput = ByteArrayOutputStream()

        val outputReader = Thread {
            try {
                process.inputStream.use { input ->
                    copyOutput(input, capturedOutput)
                }
            } catch (_: IOException) {
                // Process teardown can close the pipe while timeout handling runs.
            }
        }
        outputReader.start()

        if (!process.waitFor(timeoutMilliseconds, TimeUnit.MILLISECONDS)) {
            process.destroyForcibly()
            process.waitFor(3, TimeUnit.SECONDS)
            outputReader.join(3000)
            throw IOException("DirtyFrag timed out after $timeoutMilliseconds ms")
        }

        outputReader.join(3000)
        return ProcessOutput(
            exitStatus = process.exitValue(),
            output = sanitizeOutput(capturedOutput.toByteArray().toString(StandardCharsets.UTF_8)),
        )
    }

    private fun copyOutput(input: InputStream, output: ByteArrayOutputStream) {
        val buffer = ByteArray(8192)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) {
                return
            }
            output.write(buffer, 0, count)
        }
    }

    private fun sanitizeOutput(output: String): String {
        return output.replace(ANSI_ESCAPE_PATTERN, "")
    }

    private fun ByteArray.toHex(): String {
        return joinToString(separator = "") { byte -> "%02x".format(byte) }
    }

    private val ANSI_ESCAPE_PATTERN = "\u001B\\[[0-9;]*m".toRegex()
}
