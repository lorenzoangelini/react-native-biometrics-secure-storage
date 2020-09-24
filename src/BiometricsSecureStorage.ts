export enum BiometricsError {
    BIOMETRIC_ERROR_NO_HARDWARE = 'BIOMETRIC_ERROR_NO_HARDWARE',
    BIOMETRIC_ERROR_HW_UNAVAILABLE = 'BIOMETRIC_ERROR_HW_UNAVAILABLE',
    BIOMETRIC_ERROR_NONE_ENROLLED = 'BIOMETRIC_ERROR_NONE_ENROLLED',
    BIOMETRIC_UNSUPPORTED = 'BIOMETRIC_UNSUPPORTED',
  }
  
  export enum BiometricsTypes {
    Biometrics = 'Biometrics',
  }
  
  export interface BiometricsInfo {
    available: boolean;
    biometryType: BiometricsTypes;
    error: BiometricsError;
  }
  
  export interface BiometricsPromptConfig {
    title: string;
    subTitle: string;
    cancelText: string;
    description: string;
  }
  
  export interface BiometricsSecureStorage {
    /**
     * checks if the biometric sensor is available and can be used
     */
    isBiometricsAvailable(): Promise<BiometricsInfo>;
  
    /**
     * Start biometric authentication showing biometric prompt. On biometric success load (ad decrypt)
     * or generate (and save encrypting) the application key
     * IMPORTANT the configuration object work only on android to use custom prompt texts
     */
    authenticate(config: BiometricsPromptConfig): Promise<boolean>;
  
    /**
     * Check if the master key has been created already
     */
    isAppLocked(): Promise<boolean>;
  
    /**
     *
     * @param key SharedPreferences/UserDefaults key
     * @param data Data tu encrypt and save
     */
    encryptAndSaveData(key: string, data: string): Promise<void>;
  
    /**
     *
     * @param key SharedPreferences/UserDefaults key
  
     */
    loadAndDecryptData(key: string): Promise<string>;
  
    /**
     *
     * @param fileName Filename
     * @param data Data tu encrypt and save
     */
    encryptAndSaveDataToFile(fileName: string, data: string): Promise<void>;
  
    /**
     *
     * @param fileName Filename
     */
    loadFileAndDecryptData(fileName: string): Promise<string>;
  
    /**
     *
     * clear decoded data
     *
     */
    reset(): Promise<boolean>;
  }