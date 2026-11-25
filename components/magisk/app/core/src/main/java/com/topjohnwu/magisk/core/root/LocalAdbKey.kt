package com.topjohnwu.magisk.core.root

import android.content.Context
import android.util.Base64
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAKeyGenParameterSpec
import java.security.spec.RSAPublicKeySpec

internal class LocalAdbKey(
    val privateKey: RSAPrivateKey,
    val publicKeyBytes: ByteArray,
)

internal fun loadOrCreateLocalAdbKey(context: Context): LocalAdbKey {
    val preferences = context.getSharedPreferences(
        LOCAL_ADB_KEY_PREFERENCES,
        Context.MODE_PRIVATE,
    )
    val storedPrivateKey = preferences.getString(LOCAL_ADB_PRIVATE_KEY, null)
    val privateKey = storedPrivateKey
        ?.let(::decodePrivateKey)
        ?: generatePrivateKey().also { generatedKey ->
            preferences.edit()
                .putString(
                    LOCAL_ADB_PRIVATE_KEY,
                    Base64.encodeToString(generatedKey.encoded, Base64.NO_WRAP),
                )
                .apply()
        }

    val publicKey = KeyFactory.getInstance("RSA").generatePublic(
        RSAPublicKeySpec(
            privateKey.modulus,
            RSAKeyGenParameterSpec.F4,
        ),
    ) as RSAPublicKey

    return LocalAdbKey(
        privateKey = privateKey,
        publicKeyBytes = publicKey.toAdbPublicKey(
            "${context.packageName}@dby2-magisk",
        ),
    )
}

private fun decodePrivateKey(encodedKey: String): RSAPrivateKey? {
    return runCatching {
        KeyFactory.getInstance("RSA").generatePrivate(
            PKCS8EncodedKeySpec(
                Base64.decode(encodedKey, Base64.DEFAULT),
            ),
        ) as RSAPrivateKey
    }.getOrNull()
}

private fun generatePrivateKey(): RSAPrivateKey {
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
    keyPairGenerator.initialize(
        RSAKeyGenParameterSpec(ADB_KEY_BITS, RSAKeyGenParameterSpec.F4),
    )
    return keyPairGenerator.generateKeyPair().private as RSAPrivateKey
}

private fun RSAPublicKey.toAdbPublicKey(keyName: String): ByteArray {
    val modulusWordCount = ADB_MODULUS_BYTES / Int.SIZE_BYTES
    val wordBase = BigInteger.ONE.shiftLeft(Int.SIZE_BITS)
    val inverse = modulus.remainder(wordBase).modInverse(wordBase).negate()
    val radix = BigInteger.ONE.shiftLeft(ADB_MODULUS_BYTES * Byte.SIZE_BITS)
    val rr = radix.modPow(BigInteger.valueOf(2), modulus)

    val encoded = ByteBuffer.allocate(ADB_PUBLIC_KEY_BYTES)
        .order(ByteOrder.LITTLE_ENDIAN)
        .apply {
            putInt(modulusWordCount)
            putInt(inverse.toInt())
            modulus.toAdbWords().forEach(::putInt)
            rr.toAdbWords().forEach(::putInt)
            putInt(publicExponent.toInt())
        }
        .array()

    val encodedBase64 = Base64.encode(encoded, Base64.NO_WRAP)
    val keyNameBytes = " $keyName\u0000".toByteArray(Charsets.UTF_8)
    return encodedBase64 + keyNameBytes
}

private fun BigInteger.toAdbWords(): IntArray {
    val wordBase = BigInteger.ONE.shiftLeft(Int.SIZE_BITS)
    val words = IntArray(ADB_MODULUS_BYTES / Int.SIZE_BYTES)
    var remaining = this

    for (index in words.indices) {
        val division = remaining.divideAndRemainder(wordBase)
        remaining = division[0]
        words[index] = division[1].toInt()
    }
    return words
}

private const val LOCAL_ADB_KEY_PREFERENCES = "local_adb_key"
private const val LOCAL_ADB_PRIVATE_KEY = "private_key"
private const val ADB_KEY_BITS = 2048
private const val ADB_MODULUS_BYTES = ADB_KEY_BITS / Byte.SIZE_BITS
private const val ADB_PUBLIC_KEY_BYTES = 524
