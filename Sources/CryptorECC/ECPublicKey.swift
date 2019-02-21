//  Copyright © 2019 IBM. All rights reserved.
//
//     Licensed under the Apache License, Version 2.0 (the "License");
//     you may not use this file except in compliance with the License.
//     You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
//     Unless required by applicable law or agreed to in writing, software
//     distributed under the License is distributed on an "AS IS" BASIS,
//     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//     See the License for the specific language governing permissions and
//     limitations under the License.
//

import Foundation
#if os(macOS) || os(iOS) || os(tvOS) || os(watchOS)
import CommonCrypto
#elseif os(Linux)
import OpenSSL
#endif

/**
 A class representing an elliptic curve public key.
 Supported curves are:  
 - prime256v1  
 - secp384r1  
 - NID_secp521r1  
 You can generate an Elliptic curve Key using OpenSSL:  
 https://wiki.openssl.org/index.php/Command_Line_Elliptic_Curve_Operations#Generating_EC_Keys_and_Parameters  
 
 ### Usage Example: 
 ```swift
 let pemKey = """
 -----BEGIN PUBLIC KEY-----
 MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEikc5m6C2xtDWeeAeT18WElO37zvF
 Oz8p4kAlhvgIHN23XIClNESgKVmLgSSq2asqiwdrU5YHbcHFkgdABM1SPA==
 -----END PUBLIC KEY-----
 """
 let publicKey = try ECPublicKey(key: pemKey)
 let base64Sig = "MEYCIQCvgBLn+tQoBDBR3D2G3485GloYGNxuk6PqR4qjr5GDqAIhAKNvsqvesVBD/MLub/KAyzLLNGtUZyQDxYZj/4vmHwWF"
 let signature = try ECSignature(asn1: Data(base64Encoded: base64Sig)) 
 let verified = signature.verify(plaintext: "Hello world", using: publicKey)
 ```
 */
@available(OSX 10.12, *)
public class ECPublicKey {
    #if os(Linux)
    typealias NativeKey = OpaquePointer?
    deinit {
        EC_KEY_free(self.nativeKey)
    }
    #else
    typealias NativeKey = SecKey
    #endif
    let nativeKey: NativeKey
    let algorithm: ECAlgorithm

    /**
     Initialize an ECPublicKey from a `.pem` file format.
     ### Usage Example: ###
     ```swift
     let publicKeyString = """
     -----BEGIN PUBLIC KEY-----
     MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEikc5m6C2xtDWeeAeT18WElO37zvF
     Oz8p4kAlhvgIHN23XIClNESgKVmLgSSq2asqiwdrU5YHbcHFkgdABM1SPA==
     -----END PUBLIC KEY-----
     """
     let pemKey = try ECPublicKey(key: publicKeyString)
     ```
     */
    /// - Parameter key: The elliptic curve public key as a PEM string.
    /// - Returns: An ECPublicKey.
    /// - Throws: An ECError if the PEM string can't be decoded or is not a valid key.
    public convenience init(key: String) throws {
        let strippedKey = String(key.filter { !" \n\t\r".contains($0) })
        var pemComponents = strippedKey.components(separatedBy: "-----")
        guard pemComponents.count == 5 else {
            throw ECError.invalidPEMString
        }
        guard let der = Data(base64Encoded: pemComponents[2]) else {
            throw ECError.invalidPEMString
        }
        if pemComponents[1] == "BEGINPUBLICKEY" {
            try self.init(der: der)
        } else {
            throw ECError.unknownPEMHeader
        }
    }
    
    /// Initialize an ECPublicKey from `.der` file data.  
    /// This is equivalent to a PEM String that has had the "-----BEGIN PUBLIC KEY-----"
    /// header and footer stripped and been base64 encoded to ASN1 Data.
    /// - Parameter der: The elliptic curve public key Data.
    /// - Returns: An ECPublicKey.
    /// - Throws: An ECError if the Data can't be decoded or is not a valid key.
    public init(der: Data) throws {
        let (result, _) = ASN1.toASN1Element(data: der)
        guard case let ASN1.ASN1Element.seq(elements: seq) = result,
            seq.count > 1,
            case let ASN1.ASN1Element.seq(elements: ids) = seq[0],
            ids.count > 1,
            case let ASN1.ASN1Element.bytes(data: privateKeyID) = ids[1],
            case let ASN1.ASN1Element.bytes(data: publicKeyData) = seq[1]
        else {
            throw ECError.failedASN1Decoding
        }
        self.algorithm = try ECAlgorithm.objectToHashAlg(ObjectIdentifier: privateKeyID)
        
        #if os(Linux)
            let bigNum = BN_new()
            publicKeyData.withUnsafeBytes({ (publicKeyBytes: UnsafePointer<UInt8>) -> Void in
                BN_bin2bn(publicKeyBytes, Int32(publicKeyData.count), bigNum)
            })
            let ecKey = EC_KEY_new_by_curve_name(algorithm.curve)
            let ecGroup = EC_KEY_get0_group(ecKey)
            let ecPoint = EC_POINT_new(ecGroup)
            EC_POINT_bn2point(ecGroup, bigNum, ecPoint, nil)
            guard EC_KEY_set_public_key(ecKey, ecPoint) == 1 else {
                throw ECError.failedNativeKeyCreation
            }
            BN_free(bigNum)
            EC_POINT_free(ecPoint)
            self.nativeKey = ecKey
        #else
            let keyData = publicKeyData.drop(while: { $0 == 0x00})
            var error: Unmanaged<CFError>? = nil
            guard let secKey = SecKeyCreateWithData(keyData as CFData,
                                                    [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
                                                     kSecAttrKeyClass: kSecAttrKeyClassPublic,
                                                     kSecAttrKeySizeInBits: 256] as CFDictionary,
                                                     &error)
            else {
                if let secError = error?.takeRetainedValue() {
                    throw secError
                } else {
                    throw ECError.failedNativeKeyCreation
                }
            }
            self.nativeKey = secKey
        #endif
    }
}
