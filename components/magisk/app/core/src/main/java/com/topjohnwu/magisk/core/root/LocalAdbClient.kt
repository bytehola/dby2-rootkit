package com.topjohnwu.magisk.core.root

import android.content.Context
import android.util.Log
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.security.PrivateKey
import javax.crypto.Cipher

internal class LocalAdbClient(private val context: Context) {

    private val adbKey by lazy { loadOrCreateLocalAdbKey(context) }

    fun shell(command: String, timeoutMilliseconds: Int = DEFAULT_TIMEOUT_MILLISECONDS): String {
        Socket().use { socket ->
            try {
                socket.connect(
                    InetSocketAddress(LOOPBACK_ADDRESS, ADB_PORT),
                    CONNECT_TIMEOUT_MILLISECONDS,
                )
            } catch (error: IOException) {
                throw IOException(
                    "本机 ADB 端口 5555 未就绪。请先在开发者选项中启用 USB 调试和“仅充电”模式 ADB 调试。",
                    error,
                )
            }
            socket.soTimeout = AUTH_TIMEOUT_MILLISECONDS
            Log.d(TAG, "Connected to local adbd")

            val socketInput = socket.getInputStream()
            val socketOutput = socket.getOutputStream()

            sendPacket(
                socketOutput,
                CNXN,
                ADB_VERSION,
                MAX_PACKET_PAYLOAD,
                "host::\u0000".toByteArray(StandardCharsets.UTF_8),
            )
            try {
                authenticate(
                    socketInput,
                    socketOutput,
                    adbKey.privateKey,
                    adbKey.publicKeyBytes,
                )
            } catch (error: IOException) {
                throw IOException(
                    "本机 ADB 授权未完成。请解锁平板，允许 Magisk 的 USB 调试授权后再次点击一键 Root。",
                    error,
                )
            }
            socket.soTimeout = timeoutMilliseconds
            Log.d(TAG, "Local adbd authentication completed")

            val localStreamId = 1
            sendPacket(
                socketOutput,
                OPEN,
                localStreamId,
                0,
                ("shell:$command\u0000").toByteArray(StandardCharsets.UTF_8),
            )
            Log.d(TAG, "Opened local ADB shell service")

            var remoteStreamId = -1
            val commandOutput = ByteArrayOutputStream()
            while (true) {
                val packet = readPacket(socketInput)
                Log.d(
                    TAG,
                    "Received ${commandName(packet.command)} " +
                        "arg0=${packet.firstArgument} arg1=${packet.secondArgument} " +
                        "payload=${packet.payload.size}",
                )

                when {
                    packet.command == OKAY && packet.secondArgument == localStreamId -> {
                        remoteStreamId = packet.firstArgument
                    }

                    packet.command == WRTE && packet.secondArgument == localStreamId -> {
                        commandOutput.write(packet.payload)
                        sendPacket(
                            socketOutput,
                            OKAY,
                            localStreamId,
                            remoteStreamId,
                            ByteArray(0),
                        )
                    }

                    packet.command == CLSE -> {
                        sendPacket(
                            socketOutput,
                            CLSE,
                            localStreamId,
                            remoteStreamId,
                            ByteArray(0),
                        )
                        break
                    }

                    packet.command == FAIL -> {
                        val reason = String(packet.payload, StandardCharsets.UTF_8)
                        throw IOException("ADB shell service failed: $reason")
                    }
                }
            }

            return commandOutput.toByteArray().toString(StandardCharsets.UTF_8)
        }
    }

    private fun authenticate(
        socketInput: InputStream,
        socketOutput: OutputStream,
        privateKey: PrivateKey,
        publicKey: ByteArray,
    ) {
        var signatureAttempted = false
        repeat(MAX_AUTH_ATTEMPTS) {
            val packet = readPacket(socketInput)
            Log.d(
                TAG,
                "Auth packet ${commandName(packet.command)} " +
                    "arg0=${packet.firstArgument} payload=${packet.payload.size}",
            )
            when (packet.command) {
                CNXN -> return
                FAIL -> {
                    val reason = String(packet.payload, StandardCharsets.UTF_8)
                    throw IOException("ADB authentication failed: $reason")
                }

                AUTH -> {
                    when (packet.firstArgument) {
                        ADB_AUTH_SIGNATURE -> {
                            if (!signatureAttempted) {
                                signatureAttempted = true
                                val signature =
                                    signPrehashedSha1(privateKey, packet.payload)
                                sendPacket(
                                    socketOutput,
                                    AUTH,
                                    ADB_AUTH_SIGNATURE_RESPONSE,
                                    0,
                                    signature,
                                )
                            } else {
                                sendPacket(
                                    socketOutput,
                                    AUTH,
                                    ADB_AUTH_RSA_PUBLIC_KEY,
                                    0,
                                    publicKey,
                                )
                                Thread.sleep(AUTH_RETRY_DELAY_MILLISECONDS)
                            }
                        }

                        ADB_AUTH_RSA_PUBLIC_KEY -> {
                            sendPacket(
                                socketOutput,
                                AUTH,
                                ADB_AUTH_RSA_PUBLIC_KEY,
                                0,
                                publicKey,
                            )
                            Thread.sleep(AUTH_RETRY_DELAY_MILLISECONDS)
                        }

                        else -> throw IOException(
                            "ADB requested unsupported authentication type ${packet.firstArgument}",
                        )
                    }
                }
            }
        }

        throw IOException("ADB authentication did not complete")
    }

    private fun signPrehashedSha1(privateKey: PrivateKey, digest: ByteArray): ByteArray {
        val digestInfo = SHA1_DIGEST_INFO_PREFIX + digest
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, privateKey)
        return cipher.doFinal(digestInfo)
    }

    private fun sendPacket(
        output: OutputStream,
        command: Int,
        firstArgument: Int,
        secondArgument: Int,
        payload: ByteArray,
    ) {
        writeIntLittleEndian(output, command)
        writeIntLittleEndian(output, firstArgument)
        writeIntLittleEndian(output, secondArgument)
        writeIntLittleEndian(output, payload.size)
        writeIntLittleEndian(output, checksum(payload))
        writeIntLittleEndian(output, command.inv())
        output.write(payload)
        output.flush()
    }

    private fun readPacket(input: InputStream): Packet {
        val command = readIntLittleEndian(input)
        val firstArgument = readIntLittleEndian(input)
        val secondArgument = readIntLittleEndian(input)
        val payloadLength = readIntLittleEndian(input)
        val expectedChecksum = readIntLittleEndian(input)
        val magic = readIntLittleEndian(input)

        if (magic != command.inv()) {
            throw IOException("Invalid ADB packet magic")
        }
        if (payloadLength !in 0..MAX_PACKET_PAYLOAD) {
            throw IOException("Invalid ADB payload length $payloadLength")
        }

        val payload = ByteArray(payloadLength)
        readFully(input, payload)
        if (checksum(payload) != expectedChecksum) {
            throw IOException("Invalid ADB packet checksum")
        }

        return Packet(command, firstArgument, secondArgument, payload)
    }

    private fun checksum(payload: ByteArray): Int {
        return payload.sumOf { byte -> byte.toInt() and 0xff }
    }

    private fun readIntLittleEndian(input: InputStream): Int {
        var value = 0
        var shift = 0
        while (shift < Int.SIZE_BITS) {
            val nextByte = input.read()
            if (nextByte < 0) {
                throw EOFException("ADB connection closed")
            }
            value = value or (nextByte shl shift)
            shift += Byte.SIZE_BITS
        }
        return value
    }

    private fun writeIntLittleEndian(output: OutputStream, value: Int) {
        output.write(value and 0xff)
        output.write((value ushr 8) and 0xff)
        output.write((value ushr 16) and 0xff)
        output.write((value ushr 24) and 0xff)
    }

    private fun readFully(input: InputStream, target: ByteArray) {
        var offset = 0
        while (offset < target.size) {
            val count = input.read(target, offset, target.size - offset)
            if (count < 0) {
                throw EOFException("ADB packet payload was truncated")
            }
            offset += count
        }
    }

    private data class Packet(
        val command: Int,
        val firstArgument: Int,
        val secondArgument: Int,
        val payload: ByteArray,
    )

    companion object {
        private const val LOOPBACK_ADDRESS = "127.0.0.1"
        private const val ADB_PORT = 5555
        private const val ADB_VERSION = 0x01000000
        private const val MAX_PACKET_PAYLOAD = 256 * 1024
        private const val CONNECT_TIMEOUT_MILLISECONDS = 5000
        private const val AUTH_TIMEOUT_MILLISECONDS = 65_000
        private const val DEFAULT_TIMEOUT_MILLISECONDS = 30_000
        private const val MAX_AUTH_ATTEMPTS = 120
        private const val AUTH_RETRY_DELAY_MILLISECONDS = 500L
        private const val ADB_AUTH_SIGNATURE = 1
        private const val ADB_AUTH_SIGNATURE_RESPONSE = 2
        private const val ADB_AUTH_RSA_PUBLIC_KEY = 3
        private const val TAG = "OneTapAdb"

        private val SHA1_DIGEST_INFO_PREFIX = byteArrayOf(
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05,
            0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05,
            0x00, 0x04, 0x14,
        )

        private val CNXN = adbCommand("CNXN")
        private val AUTH = adbCommand("AUTH")
        private val OPEN = adbCommand("OPEN")
        private val OKAY = adbCommand("OKAY")
        private val WRTE = adbCommand("WRTE")
        private val CLSE = adbCommand("CLSE")
        private val FAIL = adbCommand("FAIL")

        private fun adbCommand(text: String): Int {
            return (text[0].code and 0xff) or
                ((text[1].code and 0xff) shl 8) or
                ((text[2].code and 0xff) shl 16) or
                ((text[3].code and 0xff) shl 24)
        }

        private fun commandName(command: Int): String {
            return buildString(capacity = 4) {
                repeat(4) { index ->
                    append(((command ushr (index * 8)) and 0xff).toChar())
                }
            }
        }
    }
}
