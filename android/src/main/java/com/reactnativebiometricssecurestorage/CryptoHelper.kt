package com.reactnativebiometricssecurestorage

class CryptoHelper {
  @kotlin.jvm.Throws(NoSuchPaddingException::class, NoSuchAlgorithmException::class, InvalidAlgorithmParameterException::class, java.security.InvalidKeyException::class, BadPaddingException::class, IllegalBlockSizeException::class)
  fun encryptData(data: ByteArray?, applicationKey: ByteArray?, iv: ByteArray?): ByteArray {
    val cipher: Cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(applicationKey, "AES"), IvParameterSpec(iv))
    return cipher.doFinal(data)
  }

  @kotlin.jvm.Throws(NoSuchPaddingException::class, NoSuchAlgorithmException::class, InvalidAlgorithmParameterException::class, java.security.InvalidKeyException::class, BadPaddingException::class, IllegalBlockSizeException::class)
  fun decryptData(data: ByteArray?, applicationKey: ByteArray?, iv: ByteArray?): ByteArray {
    val cipher: Cipher = Cipher.getInstance("AES/GCM/NoPadding") //actually uses PKCS#7
    cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(applicationKey, "AES"), IvParameterSpec(iv))
    return cipher.doFinal(data)
  }

  fun generateIV(size: Int): ByteArray {
    val random: java.security.SecureRandom = java.security.SecureRandom()
    val iv = ByteArray(size)
    random.nextBytes(iv)
    return iv
  }

  fun generateApplicationKey(): ByteArray {
    val random: java.security.SecureRandom = java.security.SecureRandom()
    val applicationKey = ByteArray(32)
    random.nextBytes(applicationKey)
    return applicationKey
  }

  fun byteArrayToHex(bytes: Array<Byte>): String {
    val hexChars: CharArray = "0123456789ABCDEF".toCharArray()
    val result = StringBuffer()
    for (b in bytes) {
      val octet = b.toInt()
      val firstIndex = octet and 0xF0 ushr 4
      val secondIndex = octet and 0x0F
      result.append(hexChars[firstIndex])
      result.append(hexChars[secondIndex])
    }
    return result.toString()
  }

  fun getIndexOf(toSearch: Char, tab: CharArray): Int {
    for (i in tab.indices) {
      if (tab[i] == toSearch) {
        return i
      }
    }
    return -1
  }

  fun hexToByteArray(hex: String): ByteArray {
    val template = "0123456789ABCDEF"
    val hexChars: CharArray = template.toCharArray()
    val result = ByteArray(hex.length / 2)
    var i = 0
    while (i < hex.length) {
      val firstIndex = getIndexOf(hex[i], hexChars)
      val secondIndex = getIndexOf(hex[i + 1], hexChars)
      val octet = firstIndex shl 4 or secondIndex
      result[i shr 1] = octet.toByte()
      i += 2
    }
    return result
  }
}
