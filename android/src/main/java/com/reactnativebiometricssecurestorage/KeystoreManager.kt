package com.reactnativebiometricssecurestorage

import android.content.Context
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi

@RequiresApi(api = Build.VERSION_CODES.M)
class KeystoreManager(applicationContext: Context, cryptoHelper: CryptoHelper) {
  private val IV_SIZE = 16
  private val KEY_SIZE = 256
  private val MASTER_KEY_ALIAS = "SYMMETRIC_MASTER_KEY"
  private val MASTER_ASYM_KEY_ALIAS = "ASYMMETRIC_MASTER_KEY"
  private val SHARED_PREFERENCES_NAME = "KeyStoreSettings"
  private val KEYSTORE_IV_NAME = "KeyStoreIV"
  private val applicationContext: Context
  private val cryptoHelper: CryptoHelper

  @kotlin.jvm.Throws(KeyStoreException::class, java.security.cert.CertificateException::class, NoSuchAlgorithmException::class, IOException::class, NoSuchProviderException::class, InvalidAlgorithmParameterException::class)
  fun generateMasterKeys() {
    val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore")
    ks.load(null)
    if (!ks.containsAlias(MASTER_KEY_ALIAS)) {
      generateSymmetricKey()
    }
    if (!ks.containsAlias(MASTER_ASYM_KEY_ALIAS)) {
      generateAsymmetricKeys()
    }
  }

  @kotlin.jvm.Throws(KeyStoreException::class, java.security.cert.CertificateException::class, NoSuchAlgorithmException::class, IOException::class, NoSuchProviderException::class, InvalidAlgorithmParameterException::class)
  fun forceRegenerateMasterKeys() {
    val preferences: SharedPreferences = applicationContext.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE)
    val editor: Editor = preferences.edit()
    editor.remove(KEYSTORE_IV_NAME)
    editor.commit()
    val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore")
    ks.load(null)
    ks.deleteEntry(MASTER_KEY_ALIAS)
    ks.deleteEntry(MASTER_ASYM_KEY_ALIAS)
    if (!ks.containsAlias(MASTER_KEY_ALIAS)) {
      generateSymmetricKey()
    }
    if (!ks.containsAlias(MASTER_ASYM_KEY_ALIAS)) {
      generateAsymmetricKeys()
    }
  }

  @kotlin.jvm.Throws(NoSuchProviderException::class, NoSuchAlgorithmException::class, InvalidAlgorithmParameterException::class)
  private fun generateAsymmetricKeys() {
    val keyGenerator: KeyPairGenerator = KeyPairGenerator.getInstance(
      KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
    )
    val builder: KeyGenParameterSpec.Builder = Builder(MASTER_ASYM_KEY_ALIAS,
      KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
    )
    builder.setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
      .setUserAuthenticationRequired(true)
      .setUserAuthenticationValidityDurationSeconds(-1)
    addVersionSpecificBuilderSettings(builder)
    keyGenerator.initialize(builder.build())
    keyGenerator.generateKeyPair()
  }

  @kotlin.jvm.Throws(NoSuchProviderException::class, NoSuchAlgorithmException::class, InvalidAlgorithmParameterException::class)
  private fun generateSymmetricKey() {
    val keyGenerator: KeyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
    val builder: KeyGenParameterSpec.Builder = Builder(MASTER_KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
      .setKeySize(KEY_SIZE)
      .setUserAuthenticationRequired(true)
      .setUserAuthenticationValidityDurationSeconds(-1)
    addVersionSpecificBuilderSettings(builder)
    keyGenerator.init(builder.build())
    keyGenerator.generateKey()
  }

  private fun addVersionSpecificBuilderSettings(builder: KeyGenParameterSpec.Builder) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
      builder.setUnlockedDeviceRequired(true) // these methods require API min 28
      if (applicationContext.getPackageManager().hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
        builder.setIsStrongBoxBacked(true)
      }
    }
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
      builder.setInvalidatedByBiometricEnrollment(true) // this method requires API min 24
    }
  }

  fun toObjects(bytesPrim: ByteArray): Array<Byte> {
    val B: Array<Byte> = arrayOfNulls(bytesPrim.size)
    for (i in bytesPrim.indices) {
      B[i] = java.lang.Byte.valueOf(bytesPrim[i])
    }
    return B
  }

  @get:Throws(KeyStoreException::class, java.security.cert.CertificateException::class, NoSuchAlgorithmException::class, IOException::class, UnrecoverableKeyException::class, NoSuchPaddingException::class, InvalidAlgorithmParameterException::class, java.security.InvalidKeyException::class)
  val localEncryptionCipher: Cipher
    get() {
      val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore")
      ks.load(null)
      val key: java.security.Key = ks.getKey(MASTER_KEY_ALIAS, null)
      val cipher: Cipher = Cipher.getInstance("AES/GCM/NoPadding")
      val preferences: SharedPreferences = applicationContext.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE)
      val iv: ByteArray
      return if (preferences.contains(KEYSTORE_IV_NAME)) {
        val a: String = preferences.getString(KEYSTORE_IV_NAME, "")
        if (a != null) {
          iv = cryptoHelper.hexToByteArray(a)
          val spec = GCMParameterSpec(IV_SIZE * java.lang.Byte.SIZE, iv)
          cipher.init(Cipher.DECRYPT_MODE, key, spec)
          cipher
        } else {
          throw KeyStoreException()
        }
      } else {
        cipher.init(Cipher.ENCRYPT_MODE, key, cipher.getParameters())
        val editor: Editor = preferences.edit()
        editor.putString(KEYSTORE_IV_NAME, cryptoHelper.byteArrayToHex(toObjects(cipher.getIV())))
        editor.apply()
        cipher
      }
    }

  @kotlin.jvm.Throws(BadPaddingException::class, IllegalBlockSizeException::class)
  fun encryptApplicationKey(pt: ByteArray?, cipher: Cipher): ByteArray {
    return cipher.doFinal(pt)
  }

  @kotlin.jvm.Throws(BadPaddingException::class, IllegalBlockSizeException::class)
  fun decryptApplicationKey(ct: ByteArray?, cipher: Cipher): ByteArray {
    return cipher.doFinal(ct)
  }

  @get:Throws(KeyStoreException::class, java.security.cert.CertificateException::class, NoSuchAlgorithmException::class, IOException::class, UnrecoverableKeyException::class, java.security.InvalidKeyException::class)
  val signature: java.security.Signature
    get() {
      val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore")
      ks.load(null)
      val key: PrivateKey = ks.getKey(MASTER_ASYM_KEY_ALIAS, null) as PrivateKey
      val signature: java.security.Signature = java.security.Signature.getInstance("SHA512withECDSA")
      signature.initSign(key)
      return signature
    }

  @kotlin.jvm.Throws(KeyStoreException::class, java.security.cert.CertificateException::class, NoSuchAlgorithmException::class, IOException::class, java.security.InvalidKeyException::class, java.security.SignatureException::class)
  fun verifySignature(dataSigned: ByteArray?, data: ByteArray?): Boolean {
    val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore")
    ks.load(null)
    val certificate: java.security.cert.Certificate = ks.getCertificate(MASTER_ASYM_KEY_ALIAS)
    val signature: java.security.Signature = java.security.Signature.getInstance("SHA512withECDSA")
    signature.initVerify(certificate)
    signature.update(data)
    return signature.verify(dataSigned)
  }

  init {
    this.applicationContext = applicationContext
    this.cryptoHelper = cryptoHelper
  }
}
