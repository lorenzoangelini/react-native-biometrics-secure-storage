package com.reactnativebiometricssecurestorage

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.util.Log
import androidx.annotation.RequiresApi
import android.content.Context.MODE_PRIVATE

@RequiresApi(api = Build.VERSION_CODES.LOLLIPOP)
class SecureLocalManager(applicationContext: Context) {
  private val keystoreManager: KeystoreManager
  private val cryptoHelper: CryptoHelper
  private var applicationKey: ByteArray?
  private val applicationContext: Context

  @kotlin.jvm.Throws(NoSuchPaddingException::class, java.security.InvalidKeyException::class, NoSuchAlgorithmException::class, IllegalBlockSizeException::class, BadPaddingException::class, InvalidAlgorithmParameterException::class)
  fun encryptLocalData(data: ByteArray?): ByteArray {
    val iv: ByteArray = cryptoHelper.generateIV(IV_SIZE)
    val encrypted: ByteArray = cryptoHelper.encryptData(data, applicationKey, iv)
    val both: ByteArray = Arrays.copyOf(iv, iv.size + encrypted.size)
    java.lang.System.arraycopy(encrypted, 0, both, iv.size, encrypted.size)
    return both
  }

  @kotlin.jvm.Throws(NoSuchPaddingException::class, java.security.InvalidKeyException::class, NoSuchAlgorithmException::class, IllegalBlockSizeException::class, BadPaddingException::class, InvalidAlgorithmParameterException::class)
  fun decryptLocalData(data: ByteArray): ByteArray {
    Log.d("[SecureAuthModule]", String.format("Encrypted data \"%s\"", applicationKey.toString()))
    val iv: ByteArray = Arrays.copyOfRange(data, 0, IV_SIZE)
    val ct: ByteArray = Arrays.copyOfRange(data, IV_SIZE, data.size)
    return cryptoHelper.decryptData(ct, applicationKey, iv)
  }

  @get:Throws(java.security.cert.CertificateException::class, UnrecoverableKeyException::class, NoSuchAlgorithmException::class, KeyStoreException::class, java.security.InvalidKeyException::class, NoSuchPaddingException::class, InvalidAlgorithmParameterException::class, IOException::class)
  val localEncryptionCipher: Cipher
    get() = keystoreManager.getLocalEncryptionCipher()

  fun toObjects(bytesPrim: ByteArray): Array<Byte> {
    val B: Array<Byte> = arrayOfNulls(bytesPrim.size)
    for (i in bytesPrim.indices) {
      B[i] = java.lang.Byte.valueOf(bytesPrim[i])
    }
    return B
  }

  @kotlin.jvm.Throws(BadPaddingException::class, IllegalBlockSizeException::class)
  fun loadOrGenerateApplicationKey(cipher: Cipher?) {
    val preferences: SharedPreferences = applicationContext.getSharedPreferences(SHARED_PREFERENCES_NAME, MODE_PRIVATE)
    if (preferences.contains(APPLICATION_KEY_NAME)) {
      Log.d("[SecureAuthModule]", "Key found, trying to decrypt")
      val encryptedAppKey: String = preferences.getString(APPLICATION_KEY_NAME, "")
      if (encryptedAppKey != null) {
        applicationKey = keystoreManager.decryptApplicationKey(cryptoHelper.hexToByteArray(encryptedAppKey), cipher)
        Log.d("[SecureAuthModule]", "Key decrypted successfully")
      }
    } else {
      Log.d("[SecureAuthModule]", "Key not found, first time! generating a new one")
      applicationKey = cryptoHelper.generateApplicationKey()
      val editor: Editor = preferences.edit()
      val encryptedAppKey: String = cryptoHelper.byteArrayToHex(toObjects(keystoreManager.encryptApplicationKey(applicationKey, cipher)))
      editor.putString(APPLICATION_KEY_NAME, encryptedAppKey)
      editor.apply()
      Log.d("[SecureAuthModule]", "Key generated successfully")
    }
  }

  @RequiresApi(api = Build.VERSION_CODES.LOLLIPOP)
  fun unloadApplicationKey() {
    applicationKey = null
  }

  @get:Throws(java.security.cert.CertificateException::class, UnrecoverableKeyException::class, NoSuchAlgorithmException::class, KeyStoreException::class, java.security.InvalidKeyException::class, IOException::class)
  val signature: java.security.Signature
    get() = keystoreManager.getSignature()

  @kotlin.jvm.Throws(java.security.SignatureException::class)
  fun signData(data: ByteArray?, signature: java.security.Signature): ByteArray {
    signature.update(data)
    return signature.sign()
  }

  @kotlin.jvm.Throws(java.security.cert.CertificateException::class, NoSuchAlgorithmException::class, KeyStoreException::class, java.security.SignatureException::class, java.security.InvalidKeyException::class, IOException::class)
  fun verifyDataSignature(dataSigned: ByteArray?, data: ByteArray?): Boolean {
    return keystoreManager.verifySignature(dataSigned, data)
  }

  @kotlin.jvm.Throws(java.security.cert.CertificateException::class, NoSuchAlgorithmException::class, KeyStoreException::class, NoSuchProviderException::class, InvalidAlgorithmParameterException::class, IOException::class)
  fun resetKeys() {
    keystoreManager.forceRegenerateMasterKeys()
    val preferences: SharedPreferences = applicationContext.getSharedPreferences(SHARED_PREFERENCES_NAME, MODE_PRIVATE)
    val editor: Editor = preferences.edit()
    editor.remove(APPLICATION_KEY_NAME)
    editor.commit()
    unloadApplicationKey()
  }

  companion object {
    const val SHARED_PREFERENCES_NAME = "settings"
    const val APPLICATION_KEY_NAME = "ApplicationKey"
    const val SECRET_TEXT_NAME = "Secret"
    const val IV_SIZE = 16
  }

  init {
    this.applicationContext = applicationContext
    cryptoHelper = CryptoHelper()
    keystoreManager = KeystoreManager(applicationContext, cryptoHelper)
    keystoreManager.generateMasterKeys()
  }
}
