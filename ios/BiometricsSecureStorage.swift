import Foundation
import PassKit
import LocalAuthentication
@available(iOS 11.0, *)
@objc(BiometricsSecureStorage)
class BiometricsSecureStorage: RCTEventEmitter {
  
    var resolve : RCTPromiseResolveBlock
    var reject : RCTPromiseRejectBlock
    var key: SecKey?
    var cipherTextData: Data?
    var entryName = ""
    var entryContents : String {return "Hello!"}
    var applicationKey: String?
    var simulatorKey: String { return "GbNMAf2lrQ0AAu7cuTxwojQcdLQ30Kpz" }
    
    private var biometryState: BiometryState {
        let authContext = LAContext()
        var error: NSError?
        let biometryAvailable = authContext.canEvaluatePolicy(
            LAPolicy.deviceOwnerAuthenticationWithBiometrics, error: &error)
        if let laError = error as? LAError, laError.code == LAError.Code.biometryLockout {
            return .locked
        }
        return biometryAvailable ? .available : .notAvailable
    }
  

  init(resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
    self.resolve  = resolve
    self.reject = reject
  }
  
  
  @objc func authenticate(_ locale: NSDictionary, resolve: @escaping RCTPromiseResolveBlock,
  rejecter reject: @escaping RCTPromiseRejectBlock){
       self.resolve = resolve
       self.reject = reject
    
    //Check if device has the secure enclave
    if(Device.hasSecureEnclave){
      //Retrieve the key or create the newer
      prepareKey()
      //retrieve the master key
      self.cipherTextData = UserDefaults.standard.data(forKey: "masterKey")
      
    if((self.cipherTextData) != nil){
       //Decrypt the key this key we use to encrypt the sensitive user's data
       onDecrypt()
     }else {
      
       //If i don't have the master key encrypt and after decrypt to obtain the key
       onEncrypt()
       onDecrypt()
     }
    }else {
      
      //If i'm using a simulator
         if(Device.isSimulator)
           {
           var error: NSError?
           let context = LAContext()
           if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
               let reason = "Identify yourself with simulator"
               context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) {
                   [weak self] success, authenticationError in

                   DispatchQueue.main.async {
                       if success {
                          resolve(true)
                       } else {
                         resolve(false)
                       }
                   }
               }
           } else {
               resolve(false)
           }
         } else {
          //User is not using a simulator, but the biometrics are blocked at this time. to proced the user need the unblock the face id
          resolve(false)
          
      }
      
    }
      
    
   
   
  }
  
  private func showBiometryState() {
         print(biometryState.description)
     }
  
  
   func onCreateEntryClick() {
 
    let r = KeychainHelper.createBioProtectedEntry(key: self.entryName, data: Data(self.entryContents.utf8))
        print(r == noErr ? "Entry created" : "Entry creation failed, osstatus=\(r)")
    }
  
 func onReadContextClick() {
      checkBiometryState { success in
          guard success else {
              return
          }
          let authContext = LAContext()
          let accessControl = KeychainHelper.getBioSecAccessControl()
          authContext.evaluateAccessControl(accessControl,
                                            operation: .useItem,
                                            localizedReason: "Access sample keychain entry") {
              (success, error) in
              var result = ""
              if success, let data = KeychainHelper.loadBioProtected(key: self.entryName,
                                                                     context: authContext) {
                  let dataStr = String(decoding: data, as: UTF8.self)
                  result = "Keychain entry contains: \(dataStr)"
              } else {
                  result = "Can't read entry, error: \(error?.localizedDescription ?? "-")"
              }
              DispatchQueue.main.async {
                  print(result)
              }
          }
      }
  }
  

  private func onCheckEntryClick() {
      let entryExists = KeychainHelper.available(key: self.entryName)
      print(entryExists ? "Entry exists" : "Entry doesn't exist")
  }
  
  
  
  private func checkBiometryState(_ completion: @escaping (Bool)->Void) {
     
       let bioState = self.biometryState
       guard bioState != .notAvailable else {
           print("Can't read entry, biometry not available")
           completion(false)
           return
       }
    

       if bioState == .locked {
           // To unlock biometric authentication iOS requires user to enter a valid passcode
           let authContext = LAContext()
           authContext.evaluatePolicy(LAPolicy.deviceOwnerAuthentication,
                                      localizedReason: "Access sample keychain entry",
                                      reply: { (success, error) in
               DispatchQueue.main.async {
                   if success {
                       completion(true)
                   } else {
                       print("Can't read entry, error: \(error?.localizedDescription ?? "-")")
                       completion(false)
                   }
               }
           })
       } else {
           completion(true)
       }
   }
  
  
  
  private func prepareKey() -> Bool {
    //check IF key is not null exit
      guard key == nil else {
          return true
      }
    
    var secureEnclaveAllocation = UserDefaults.standard.string(forKey: "secureEnclaveAllocation")
    
    if(secureEnclaveAllocation == nil) {
      secureEnclaveAllocation = String.random()
      UserDefaults.standard.set(secureEnclaveAllocation, forKey: "secureEnclaveAllocation")
    }
  
      //check if the masterKey  is present in secure enclave and get, if it is present exit
      key = KeychainHelper.loadKey(name: secureEnclaveAllocation!)
      guard key == nil else {
          return true
      }
      do {
        //if masterKey not exist, we create a new secure enclave with biometric key
          key = try KeychainHelper.makeAndStoreKey(name: secureEnclaveAllocation!,
                                                   requiresBiometry: true)
          return true
      } catch _ {
        //catch the error when generate the key
      }
      return false
  }
  
   func onDecrypt() {
      guard prepareKey() else {
        
          self.reject("Error", "Can't decrypt", nil)
          return
      }
      guard cipherTextData != nil else {
          self.reject("Error", "Can't decrypt", nil)
          return
      }

      let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA256AESGCM
      
      guard SecKeyIsAlgorithmSupported(self.key!, .decrypt, algorithm) else {
          self.reject("Error", "Can't decrypt this algorithm", nil)
          return
      }
      
      // SecKeyCreateDecryptedData call is blocking when the used key
      // is protected by biometry authentication. If that's not the case,
      // dispatching to a background thread isn't necessary.
      DispatchQueue.global().async {
          var error: Unmanaged<CFError>?
          let clearTextData = SecKeyCreateDecryptedData(self.key!,
                                                        algorithm,
                                                        self.cipherTextData! as CFData,
                                                        &error) as Data?
          DispatchQueue.main.async {
              guard clearTextData != nil else {
                
                let errorRef = error!.takeRetainedValue().localizedDescription
                if errorRef.contains("setoken: unable to compute shared secret") {
                  //the master key is corrputed
                  self.applicationKey = nil
                  self.key = nil
                  UserDefaults.standard.removeObject(forKey: "secureEnclaveAllocation")
                  UserDefaults.standard.removeObject(forKey: "masterKey")
                  self.reject("Error", "Key permanently invalidated", nil)
                  return
                }
                self.reject("Error", "Can't decrypt", nil)
                                 return
                  
              }
             let clearText = String(decoding: clearTextData!, as: UTF8.self)
             self.applicationKey = clearText
             self.resolve(true)
          }
      }
    
  }
  
  

  @objc func encryptAndSaveData(_ key: NSString , value: NSString, resolve: @escaping RCTPromiseResolveBlock,
  rejecter reject: @escaping RCTPromiseRejectBlock){
    
    
    let valueString =  value as String
    let keyString = key as String
    
    do {
      let encriptionKey = Device.isSimulator ? simulatorKey : applicationKey!
      let encryptedValue = try valueString.aesEncrypt(key: encriptionKey)
         UserDefaults.standard.set(encryptedValue, forKey: keyString)
         resolve(true)
        
    } catch {
      resolve(false)
    }
    
  }
  
  
  @objc func loadAndDecryptData(_ key: NSString, resolve: @escaping RCTPromiseResolveBlock,
  rejecter reject: @escaping RCTPromiseRejectBlock){
  
    let keyString = key as String
      do {
      let encryptedValue = UserDefaults.standard.string(forKey: keyString)
      let decryptionKey = Device.isSimulator ? simulatorKey : applicationKey!
      let decryptedValue = try encryptedValue?.aesDecrypt(key:  decryptionKey)
             resolve(decryptedValue)
       } catch {
          resolve(nil)
       }
  }
  
  @objc func isBiometricsAvailable(_ resolve: @escaping RCTPromiseResolveBlock,
  rejecter reject: @escaping RCTPromiseRejectBlock){
    
    
    
      let result :NSDictionary = [
          "available": biometryState.description == "available" ?  Device.hasBiometrics : false,
          "biometryType" : Device.biometricsTypes,
          "error":   biometryState.description == "available" ? "" :  biometryState.description,
          "biometryStatus": biometryState.description
          ]
    
       resolve(result)

  }
  
   @objc func reset(_ resolve: @escaping RCTPromiseResolveBlock,
   rejecter reject: @escaping RCTPromiseRejectBlock){
        self.applicationKey  = nil
        self.key  = nil
        self.cipherTextData = nil
        resolve(true)
   }
  
  
  override func supportedEvents() -> [String]! {
     return ["onAppleResponse", "onChangeKeychainStatus"]
   }
  
  override static func requiresMainQueueSetup() -> Bool {
    return true
  }
  
 func onEncrypt() -> Void {
      guard prepareKey() else {
          return
      }
      guard let publicKey = SecKeyCopyPublicKey(key!) else {
        
        self.reject("Error", "Can't retrieve the public key", nil)
          return
      }
    let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA256AESGCM
    guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, algorithm) else {
           self.reject("Error", "Can't encrypt", nil)
             return
         }
         var error: Unmanaged<CFError>?

         let randomString = String.random()
         let clearTextData = randomString.data(using: .utf8)!
         cipherTextData = SecKeyCreateEncryptedData(publicKey, algorithm,
                                                    clearTextData as CFData,
                                                    &error) as Data?
         guard cipherTextData != nil else {
              self.reject("Error", "Can't encrypt", nil)
             return
         }
        //If we check the string let cipherTextHex = cipherTextData!.toHexString()
  
         //Save the crypted master key on user defaults
         UserDefaults.standard.set(cipherTextData, forKey: "masterKey")
  }
  
}
