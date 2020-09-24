//
//  Device.swift
//  BiometricsSecureStorage
//
//  Created by Lorenzo Angelini on 24/09/2020.
//  Copyright © 2020 Facebook. All rights reserved.
//

import Foundation
import LocalAuthentication

enum Device {

//To check that device has secure enclave or not
public static var hasSecureEnclave: Bool {
    return !isSimulator && hasBiometrics
}

//To Check that this is this simulator
public static var isSimulator: Bool {
    return TARGET_OS_SIMULATOR == 1
}

//Check that this device has Biometrics features available
public static var hasBiometrics: Bool {

    //Local Authentication Context
    let localAuthContext = LAContext()
    var error: NSError?

    /// Policies can have certain requirements which, when not satisfied, would always cause
    /// the policy evaluation to fail - e.g. a passcode set, a fingerprint
    /// enrolled with Touch ID or a face set up with Face ID. This method allows easy checking
    /// for such conditions.
    var isValidPolicy = localAuthContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)

    guard isValidPolicy == true else {

        if #available(iOS 11, *) {

            if error!.code != LAError.biometryNotAvailable.rawValue {
                isValidPolicy = true
            } else{
                isValidPolicy = false
            }
        }
        else {
            if error!.code != LAError.touchIDNotAvailable.rawValue {
                isValidPolicy = true
            }else{
                isValidPolicy = false
            }
        }
        return isValidPolicy
    }
    return isValidPolicy
}


  //Check type device biometric type
  public static var biometricsTypes : String {
     var error: NSError?
      //Local Authentication Context
      let localAuthContext = LAContext()
      var isValidPolicy = localAuthContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
      return localAuthContext.biometryType == LABiometryType.faceID ? "Face ID" : "Touch ID"
  }


}
