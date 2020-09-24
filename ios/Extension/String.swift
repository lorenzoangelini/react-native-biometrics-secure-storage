//
//  String.swift
//  BiometricsSecureStorage
//
//  Created by Lorenzo Angelini on 24/09/2020.
//  Copyright © 2020 Facebook. All rights reserved.
//

import Foundation
import CryptoSwift

extension String {
   var data:          Data  { return Data(utf8) }
   var base64Encoded: Data  { return data.base64EncodedData() }
   var base64Decoded: Data? { return Data(base64Encoded: self) }
  

  func aesEncrypt(key: String) throws -> String {

         var result = ""

         do {

             let key: [UInt8] = Array(key.utf8) as [UInt8]
             let aes = try! AES(key: key, blockMode: ECB(), padding: .pkcs5) // AES128 .ECB pkcs7
             let encrypted = try aes.encrypt(Array(self.utf8))

             result = encrypted.toBase64()!

             print("AES Encryption Result: \(result)")

         } catch {

             print("Error: \(error)")
         }

         return result
     }

     func aesDecrypt(key: String) throws -> String {

         var result = ""

         do {

             let encrypted = self
             let key: [UInt8] = Array(key.utf8) as [UInt8]
             let aes = try! AES(key: key, blockMode: ECB(), padding: .pkcs5) // AES128 .ECB pkcs7
             let decrypted = try aes.decrypt(Array(base64: encrypted))

             result = String(data: Data(decrypted), encoding: .utf8) ?? ""

             print("AES Decryption Result: \(result)")

         } catch {

             print("Error: \(error)")
         }

         return result
     }
  

  

    static func random(length: Int = 32) -> String {
        let base = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        var randomString: String = ""

        for _ in 0..<length {
            let randomValue = arc4random_uniform(UInt32(base.count))
            randomString += "\(base[base.index(base.startIndex, offsetBy: Int(randomValue))])"
        }
        return randomString
    }
}

extension Data {
  var string: String? { return String(data: self, encoding: .utf8) }
  public func toHexString() -> String {
        return reduce("", {$0 + String(format: "%02X ", $1)})
    }
  struct HexEncodingOptions: OptionSet {
         let rawValue: Int
         static let upperCase = HexEncodingOptions(rawValue: 1 << 0)
     }

     func hexEncodedString(options: HexEncodingOptions = []) -> String {
         let hexDigits = Array((options.contains(.upperCase) ? "0123456789ABCDEF" : "0123456789abcdef").utf16)
         var chars: [unichar] = []
         chars.reserveCapacity(2 * count)
         for byte in self {
             chars.append(hexDigits[Int(byte / 16)])
             chars.append(hexDigits[Int(byte % 16)])
         }
         return String(utf16CodeUnits: chars, count: chars.count)
     }
}

