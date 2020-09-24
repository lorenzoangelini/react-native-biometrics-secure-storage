package com.reactnativebiometricssecurestorage

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi

@RequiresApi(api = Build.VERSION_CODES.M)
class KeyStoreHelper(private val TYPE: Type) {
  enum class Type {
    SYMMETRIC, ASYMMETRIC
  }

  private val MASTER_KEY_ALIAS = "MASTER_KEY"

  @kotlin.jvm.Throws(KeyStoreException::class, java.security.cert.CertificateException::class, NoSuchAlgorithmException::class, IOException::class, NoSuchProviderException::class, InvalidAlgorithmParameterException::class)
  fun generateMasterKey() {
    val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore")
    ks.load(null)
    if (ks.containsAlias(MASTER_KEY_ALIAS)) {
      return
    }
    if (TYPE == Type.ASYMMETRIC) {
      val keyGenerator: KeyPairGenerator = KeyPairGenerator.getInstance(
        KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore"
      )
      keyGenerator.initialize(
        Builder(MASTER_KEY_ALIAS,
          KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
          .setDigests(
            KeyProperties.DIGEST_SHA256,
            KeyProperties.DIGEST_SHA512
          )
          .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
          .setUserAuthenticationRequired(true)
          .build()
      )
      keyGenerator.generateKeyPair()
    } else {
      val keyGenerator: KeyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
      keyGenerator.init(
        Builder(MASTER_KEY_ALIAS,
          KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
          .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
          .setUserAuthenticationRequired(true)
          .build()
      )
      keyGenerator.generateKey()
    }
  }

  @get:Throws(KeyStoreException::class, java.security.cert.CertificateException::class, NoSuchAlgorithmException::class, IOException::class, UnrecoverableKeyException::class, NoSuchPaddingException::class, java.security.InvalidKeyException::class)
  val cipher: Cipher
    get() {
      val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore")
      ks.load(null)
      val key: PrivateKey = ks.getKey(MASTER_KEY_ALIAS, null) as PrivateKey
      val cipher: Cipher
      cipher = if (TYPE == Type.ASYMMETRIC) {
        Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
      } else {
        Cipher.getInstance("AES/GCM/NoPadding")
      }
      cipher.init(Cipher.DECRYPT_MODE, key)
      return cipher
    }

  @kotlin.jvm.Throws(KeyStoreException::class, java.security.cert.CertificateException::class, NoSuchAlgorithmException::class, IOException::class, NoSuchPaddingException::class, InvalidAlgorithmParameterException::class, java.security.InvalidKeyException::class)
  fun encryptApplicationKey(pt: ByteArray?): ByteArray {
    val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore")
    ks.load(null)
    val key: PublicKey = ks.getCertificate(MASTER_KEY_ALIAS).getPublicKey()
    return if (TYPE == Type.ASYMMETRIC) {
      val spec = OAEPParameterSpec(
        "SHA-256",
        "MGF1",
        MGF1ParameterSpec.SHA1,
        PSource.PSpecified.DEFAULT
      )
      val cipher: Cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
      cipher.init(Cipher.ENCRYPT_MODE, key, spec)
      try {
        cipher.doFinal(pt)
      } catch (e: BadPaddingException) {
        throw java.lang.IllegalArgumentException("ENCRYPTION ERROR!")
      } catch (e: IllegalBlockSizeException) {
        throw java.lang.IllegalArgumentException("ENCRYPTION ERROR!")
      }
    } else {
      val iv = ByteArray(16)
      Random().nextBytes(iv)
      //TODO: save IV
      val spec = GCMParameterSpec(16 * java.lang.Byte.SIZE, iv)
      val cipher: Cipher = Cipher.getInstance("AES/GCM/NoPadding")
      cipher.init(Cipher.ENCRYPT_MODE, key, spec)
      try {
        cipher.doFinal(pt)
      } catch (e: BadPaddingException) {
        throw java.lang.IllegalArgumentException("ENCRYPTION ERROR!")
      } catch (e: IllegalBlockSizeException) {
        throw java.lang.IllegalArgumentException("ENCRYPTION ERROR!")
      }
    }
  }

  fun decryptApplicationKey(ct: ByteArray?, cipher: Cipher): ByteArray {
    return try {
      cipher.doFinal(ct)
    } catch (e: BadPaddingException) {
      throw java.lang.IllegalArgumentException("ENCRYPTION ERROR!")
    } catch (e: IllegalBlockSizeException) {
      throw java.lang.IllegalArgumentException("ENCRYPTION ERROR!")
    }
  }

}
