package com.reactnativebiometricssecurestorage

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.util.Base64
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity

class SecureDataHandler private constructor(applicationContext: Context) {
  abstract class AuthCallback {
    abstract fun onSuccess()
    abstract fun onFailure()
    abstract fun onError(message: String?, e: java.lang.Exception?)
    abstract fun onError(message: String?)
  }

  private val applicationContext: Context
  private var secureLocalManager: SecureLocalManager? = null
  val isAppLocked: Boolean
    get() {
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
        val preferences: SharedPreferences = applicationContext.getSharedPreferences(SecureLocalManager.SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE)
        return preferences.contains(SecureLocalManager.APPLICATION_KEY_NAME)
      }
      return false
    }

  fun unloadApplicationKey() {
    secureLocalManager.unloadApplicationKey()
  }

  @kotlin.jvm.Throws(java.security.cert.CertificateException::class, NoSuchAlgorithmException::class, KeyStoreException::class, NoSuchProviderException::class, InvalidAlgorithmParameterException::class, IOException::class)
  fun resetKeys() {
    secureLocalManager.resetKeys()
  }

  @RequiresApi(api = Build.VERSION_CODES.M)
  @kotlin.jvm.Throws(NoSuchPaddingException::class, InvalidAlgorithmParameterException::class, NoSuchAlgorithmException::class, IllegalBlockSizeException::class, BadPaddingException::class, java.security.InvalidKeyException::class)
  fun encryptAndSaveData(preferencesKey: String?, dataToSave: String) {
    val encrypted: ByteArray = secureLocalManager.encryptLocalData(dataToSave.toByteArray())
    val b64: String = Base64.encodeToString(encrypted, Base64.NO_WRAP)
    Log.d("[SecureAuthModule]", String.format("Clear data \"%s\", encrypted data \"%s\"", dataToSave, b64))
    val preferences: SharedPreferences = applicationContext.getSharedPreferences(SecureLocalManager.SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE)
    val editor: Editor = preferences.edit()
    editor.putString(preferencesKey, b64)
    editor.apply()
  }

  @RequiresApi(api = Build.VERSION_CODES.M)
  @kotlin.jvm.Throws(NoSuchPaddingException::class, InvalidAlgorithmParameterException::class, NoSuchAlgorithmException::class, IllegalBlockSizeException::class, BadPaddingException::class, java.security.InvalidKeyException::class)
  fun loadAndDecryptData(preferencesKey: String?): String {
    val preferences: SharedPreferences = applicationContext.getSharedPreferences(SecureLocalManager.SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE)
    val encrypted: String = preferences.getString(preferencesKey, "")
    Log.d("[SecureAuthModule]", String.format("Encrypted data \"%s\"", encrypted))
    val decrypted: ByteArray = secureLocalManager.decryptLocalData(Base64.decode(encrypted, Base64.NO_WRAP))
    Log.d("[SecureAuthModule]", String.format("Encrypted data \"%s\", decrypted data \"%s\"", encrypted, String(decrypted)))
    return String(decrypted)
  }

  @RequiresApi(api = Build.VERSION_CODES.M)
  @kotlin.jvm.Throws(NoSuchPaddingException::class, InvalidAlgorithmParameterException::class, NoSuchAlgorithmException::class, IllegalBlockSizeException::class, BadPaddingException::class, java.security.InvalidKeyException::class, IOException::class)
  fun encryptAndSaveDataToFile(filePath: String?, dataToSave: String) {
    val encrypted: ByteArray = secureLocalManager.encryptLocalData(dataToSave.toByteArray())
    FileUtils.writeFile(filePath, encrypted)
  }

  @RequiresApi(api = Build.VERSION_CODES.M)
  @kotlin.jvm.Throws(NoSuchPaddingException::class, InvalidAlgorithmParameterException::class, NoSuchAlgorithmException::class, IllegalBlockSizeException::class, BadPaddingException::class, java.security.InvalidKeyException::class, IOException::class)
  fun loadFileAndDecryptData(filePath: String?): String {
    var startTime: Long = java.lang.System.currentTimeMillis()
    val data: ByteArray = FileUtils.readFile(filePath)
    var stopTime: Long = java.lang.System.currentTimeMillis()
    Log.d("[SecureAuthModule]", String.format("Reading file required %f", (stopTime.toDouble() - startTime) / 1000))
    startTime = java.lang.System.currentTimeMillis()
    val decrypted: ByteArray = secureLocalManager.decryptLocalData(data)
    stopTime = java.lang.System.currentTimeMillis()
    Log.d("[SecureAuthModule]", String.format("Complete decryption required %f", (stopTime.toDouble() - startTime) / 1000))
    return String(decrypted)
  }

  @RequiresApi(api = Build.VERSION_CODES.M)
  @kotlin.jvm.Throws(java.security.cert.CertificateException::class, UnrecoverableKeyException::class, NoSuchAlgorithmException::class, KeyStoreException::class, InvalidAlgorithmParameterException::class, NoSuchPaddingException::class, java.security.InvalidKeyException::class, IOException::class)
  fun authenticate(activity: FragmentActivity?, callback: AuthCallback, texts: PromptTexts) {
    val cipher: Cipher = secureLocalManager.getLocalEncryptionCipher()
    val executor: Executor = Executors.newSingleThreadExecutor()
    val biometricPrompt = BiometricPrompt(activity, executor, object : AuthenticationCallback() {
      fun onAuthenticationError(errorCode: Int, @NonNull errString: CharSequence) {
        //TODO
        callback.onError(errString.toString())
      }

      fun onAuthenticationSucceeded(@NonNull result: BiometricPrompt.AuthenticationResult) {
        val cryptoObject: BiometricPrompt.CryptoObject = result.getCryptoObject()
        if (cryptoObject != null) {
          val cipher: Cipher = cryptoObject.getCipher()
          try {
            secureLocalManager.loadOrGenerateApplicationKey(cipher)
            callback.onSuccess()
          } catch (e: java.lang.Exception) {
            Log.e("[SecureAuthModule]", e.message, e)
            callback.onError(e.message)
          }
        }
      }

      fun onAuthenticationFailed() {
        //TODO
        callback.onFailure()
      }
    })
    val promptInfo: BiometricPrompt.PromptInfo = Builder()
      .setDeviceCredentialAllowed(false)
      .setNegativeButtonText(texts.cancelText)
      .setTitle(texts.title)
      .setSubtitle(texts.subTitle)
      .setDescription(texts.description)
      .build()
    val crypto: BiometricPrompt.CryptoObject = CryptoObject(cipher)
    biometricPrompt.authenticate(promptInfo, crypto)
  }

  class PromptTexts(val title: String, val subTitle: String, val cancelText: String, val description: String)

  companion object {
    var instance: SecureDataHandler? = null
      private set

    fun init(applicationContext: Context) {
      if (instance == null) {
        instance = SecureDataHandler(applicationContext)
      }
    }

  }

  init {
    this.applicationContext = applicationContext
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
      try {
        secureLocalManager = SecureLocalManager(applicationContext)
      } catch (e: java.lang.Exception) {
        Log.e("[SecureAuthModule]", e.message, e)
      }
    }
  }
}
