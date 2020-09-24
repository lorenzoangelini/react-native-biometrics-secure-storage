package com.reactnativebiometricssecurestorage

import android.os.Build
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.util.Log
import androidx.biometric.BiometricManager
import androidx.fragment.app.FragmentActivity
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.UiThreadUtil
import com.facebook.react.bridge.WritableMap
import com.facebook.react.bridge.WritableNativeMap
import com.reactnativebiometricssecurestorage.DecryptFileTask
import com.reactnativebiometricssecurestorage.tasks.EncryptFileTask

class BiometricsSecureStorageModule(reactContext: ReactApplicationContext) : ReactContextBaseJavaModule(reactContext) {
  private val reactContext: ReactApplicationContext
  val name: String
    get() = "BiometricsSecureStorage"

  @ReactMethod
  fun isBiometricsAvailable(promise: Promise) {
    try {
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
        val reactApplicationContext: ReactApplicationContext = getReactApplicationContext()
        val biometricManager: BiometricManager = BiometricManager.from(reactApplicationContext)
        val canAuthenticate: Int = biometricManager.canAuthenticate()
        if (canAuthenticate == BiometricManager.BIOMETRIC_SUCCESS) {
          val resultMap: WritableMap = WritableNativeMap()
          resultMap.putBoolean("available", true)
          resultMap.putString("biometryType", "Biometrics")
          promise.resolve(resultMap)
        } else {
          val resultMap: WritableMap = WritableNativeMap()
          resultMap.putBoolean("available", false)
          when (canAuthenticate) {
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> resultMap.putString("error", "BIOMETRIC_ERROR_NO_HARDWARE")
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> resultMap.putString("error", "BIOMETRIC_ERROR_HW_UNAVAILABLE")
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> resultMap.putString("error", "BIOMETRIC_ERROR_NONE_ENROLLED")
          }
          promise.resolve(resultMap)
        }
      } else {
        val resultMap: WritableMap = WritableNativeMap()
        resultMap.putBoolean("available", false)
        resultMap.putString("error", "BIOMETRIC_UNSUPPORTED")
        promise.resolve(resultMap)
      }
    } catch (e: java.lang.Exception) {
      Log.e("[SecureAuthModule]", e.message, e)
      promise.reject("Error detecting biometrics availability: " + e.message, "Error detecting biometrics availability: " + e.message)
    }
  }

  @ReactMethod
  fun isAppLocked(promise: Promise) {
    promise.resolve(SecureDataHandler.getInstance().isAppLocked())
  }

  @ReactMethod
  fun encryptAndSaveData(key: String?, data: String?, promise: Promise) {
    Log.d("[SecureAuthModule]", String.format("Encrypting data with key %s", key))
    try {
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
        UiThreadUtil.runOnUiThread(
          object : Runnable {
            override fun run() {
              try {
                SecureDataHandler.getInstance().encryptAndSaveData(key, data)
                Log.d("[SecureAuthModule]", String.format("Data for key %s encrypted successfully", key))
                promise.resolve(null)
              } catch (e: java.lang.Exception) {
                Log.e("[SecureAuthModule]", e.message, e)
                promise.reject(e)
              }
            }
          }
        )
      } else {
        throw UnsupportedOperationException("Min api version is 23")
      }
    } catch (e: java.lang.Exception) {
      Log.e("[SecureAuthModule]", e.message, e)
      promise.reject(e)
    }
  }

  @ReactMethod
  fun loadAndDecryptData(key: String?, promise: Promise) {
    Log.d("[SecureAuthModule]", String.format("Decrypting data with key %s", key))
    try {
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
        UiThreadUtil.runOnUiThread(
          object : Runnable {
            override fun run() {
              try {
                val decryptedData: String = SecureDataHandler.getInstance().loadAndDecryptData(key)
                Log.d("[SecureAuthModule]", String.format("Data for key %s decrypted successfully", key))
                promise.resolve(decryptedData)
              } catch (e: java.lang.Exception) {
                Log.e("[SecureAuthModule]", e.message, e)
                promise.reject(e)
              }
            }
          }
        )
      } else {
        throw UnsupportedOperationException("Min api version is 23")
      }
    } catch (e: java.lang.Exception) {
      Log.e("[SecureAuthModule]", e.message, e)
      promise.reject(e)
    }
  }

  @ReactMethod
  fun encryptAndSaveDataToFile(filePath: String?, data: String?, promise: Promise) {
    Log.d("[SecureAuthModule]", String.format("Encrypting data with filePath %s", filePath))
    try {
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
        val dir: java.io.File = reactContext.getFilesDir()
        val realFile: java.io.File = java.io.File(dir, filePath)
        EncryptFileTask(promise, data, realFile.getAbsolutePath())
          .execute()
      } else {
        throw UnsupportedOperationException("Min api version is 23")
      }
    } catch (e: java.lang.Exception) {
      Log.e("[SecureAuthModule]", e.message, e)
      promise.reject(e)
    }
  }

  @ReactMethod
  fun loadFileAndDecryptData(filePath: String?, promise: Promise) {
    Log.d("[SecureAuthModule]", String.format("Decrypting data with filePath %s", filePath))
    try {
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
        val dir: java.io.File = reactContext.getFilesDir()
        val realFile: java.io.File = java.io.File(dir, filePath)
        DecryptFileTask(promise, realFile.getAbsolutePath())
          .execute()
      } else {
        throw UnsupportedOperationException("Min api version is 23")
      }
    } catch (e: java.lang.Exception) {
      Log.e("[SecureAuthModule]", e.message, e)
      promise.reject(e)
    }
  }

  /**
   *
   * @param callback
   * @param options should be like: {title:'title', subTitle:'subTitle', cancelText:'cancelText', description:'description'}
   */
  @ReactMethod
  fun authenticate(options: ReadableMap, callback: Promise) {
    try {
      Log.d("[SecureAuthModule]", "authenticate")
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
        val config: SecureDataHandler.PromptTexts = PromptTexts(
          options.getString("title"),
          options.getString("subTitle"),
          options.getString("cancelText"),
          options.getString("description")
        )
        UiThreadUtil.runOnUiThread(
          object : Runnable {
            override fun run() {
              try {
                SecureDataHandler.getInstance().authenticate(getCurrentActivity() as FragmentActivity?, object : AuthCallback() {
                  fun onSuccess() {
                    callback.resolve(true)
                  }

                  fun onFailure() {
                    callback.resolve(false)
                  }

                  fun onError(message: String?, e: java.lang.Exception?) {
                    callback.reject(e)
                  }

                  fun onError(message: String?) {
                    callback.reject("ERROR_AUTH", message)
                  }
                }, config)
              } catch (e: KeyPermanentlyInvalidatedException) {
                // When a user add a fingerprint the key is invalidated so it must be recreated
                try {
                  SecureDataHandler.getInstance().resetKeys()
                  callback.reject(e)
                } catch (ex: java.lang.Exception) {
                  callback.reject(ex)
                }
              } catch (e: java.lang.Exception) {
                callback.reject(e)
              }
            }
          }
        )
      } else {
        throw UnsupportedOperationException("Min api version is 23")
      }
    } catch (e: java.lang.Exception) {
      Log.e("[SecureAuthModule]", e.message, e)
      callback.reject(e)
    }
  }

  @ReactMethod
  fun logout() {
    SecureDataHandler.getInstance().unloadApplicationKey()
  }

  companion object {
    private val taskQueue: LinkedBlockingQueue<Runnable> = LinkedBlockingQueue<Runnable>()
    private val threadPool: ThreadPoolExecutor = ThreadPoolExecutor(5, 10, 5000, TimeUnit.MILLISECONDS, taskQueue)
  }

  init {
    this.reactContext = reactContext
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
      Log.d("[SecureAuthModule]", "Creating SecureDataHandler")
      try {
        SecureDataHandler.init(this.reactContext)
      } catch (e: java.lang.Exception) {
        Log.e("[SecureAuthModule]", e.message, e)
      }
    }
  }
}
