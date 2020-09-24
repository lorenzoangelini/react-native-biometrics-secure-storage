//
//  BiometryState.swift
//  BiometricsSecureStorage
//
//  Created by Lorenzo Angelini on 24/09/2020.
//  Copyright © 2020 Facebook. All rights reserved.
//

import Foundation

enum BiometryState: CustomStringConvertible {
       case available, locked, notAvailable
       
       var description: String {
           switch self {
           case .available:
               return "available"
           case .locked:
               return "locked (temporarily)"
           case .notAvailable:
               return "notAvailable (turned off/not enrolled)"
           }
       }
   }
