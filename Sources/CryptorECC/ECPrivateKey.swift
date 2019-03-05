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
 Represents an elliptic curve private key.  
 Supported curves are:  
 - prime256v1  
 - secp384r1  
 - NID_secp521r1  
 You can generate an elliptic curve Key using OpenSSL:  
 https://wiki.openssl.org/index.php/Command_Line_Elliptic_Curve_Operations#Generating_EC_Keys_and_Parameters
 
 ### Usage Example: 
 ```swift
 let pemKey = """
 -----BEGIN EC PRIVATE KEY-----
 MHcCAQEEIJX+87WJ7Gh19sohyZnhxZeXYNOcuGv4Q+8MLge4UkaZoAoGCCqGSM49
 AwEHoUQDQgAEikc5m6C2xtDWeeAeT18WElO37zvFOz8p4kAlhvgIHN23XIClNESg
 KVmLgSSq2asqiwdrU5YHbcHFkgdABM1SPA==
 -----END EC PRIVATE KEY-----
 """
 let privateKey = try ECPrivateKey(key: pemKey)
 let signature = "Hello world".sign(with: privateKey)
 ```
 */
@available(OSX 10.13, *)
public class ECPrivateKey {
    /// The Elliptic curve this key was generated from.
    public let curve: Curve
    #if os(Linux)
        typealias NativeKey = OpaquePointer?
        deinit { EC_KEY_free(.make(optional: self.nativeKey)) }
    #else
        typealias NativeKey = SecKey
    #endif
    let nativeKey: NativeKey
    let pubKeyBytes: Data


    /**
     Initialize an ECPrivateKey from a PEM String.
     This can either be from a `.p8` file with the header "-----BEGIN PRIVATE KEY-----",
     or from a `.pem` file with the header "-----BEGIN EC PRIVATE KEY-----".
     ### Usage Example: ###
     ```swift
     let privateKeyString = """
     -----BEGIN EC PRIVATE KEY-----
     MHcCAQEEIJX+87WJ7Gh19sohyZnhxZeXYNOcuGv4Q+8MLge4UkaZoAoGCCqGSM49
     AwEHoUQDQgAEikc5m6C2xtDWeeAeT18WElO37zvFOz8p4kAlhvgIHN23XIClNESg
     KVmLgSSq2asqiwdrU5YHbcHFkgdABM1SPA==
     -----END EC PRIVATE KEY-----
     """
     let key = try ECPrivateKey(key: privateKeyString)
     ```
     - Parameter key: The elliptic curve private key as a PEM string.
     - Returns: An ECPrivateKey.
     - Throws: An ECError if the PEM string can't be decoded or is not a valid key.
     */
    public convenience init(key: String) throws {
        // Strip whitespace characters
        let strippedKey = String(key.filter { !" \n\t\r".contains($0) })
        var pemComponents = strippedKey.components(separatedBy: "-----")
        guard pemComponents.count >= 5 else {
            throw ECError.invalidPEMString
        }
        // Remove any EC parameters since Curve is determined by OID
        if pemComponents[1]  == "BEGINECPARAMETERS" {
            pemComponents.removeFirst(5)
            guard pemComponents.count >= 5 else {
                throw ECError.invalidPEMString
            }
        }
        guard let der = Data(base64Encoded: pemComponents[2]) else {
            throw ECError.failedBase64Encoding
        }
        if pemComponents[1] == "BEGINECPRIVATEKEY" {
            try self.init(sec1DER: der)
        } else if pemComponents[1] == "BEGINPRIVATEKEY" {
            try self.init(pkcs8DER: der)
        } else {
            throw ECError.unknownPEMHeader
        }
    }

    /// Initialize an ECPrivateKey from a PKCS8 `.der` file data.  
    /// This is equivalent to a PEM String that has had the "-----BEGIN PRIVATE KEY-----"
    /// header and footer stripped and been base64 encoded to ASN1 Data.
    /// - Parameter pkcs8DER: The elliptic curve private key Data.
    /// - Returns: An ECPrivateKey.
    /// - Throws: An ECError if the Data can't be decoded or is not a valid key.
    public init(pkcs8DER: Data) throws {
        let (result, _) = ASN1.toASN1Element(data: pkcs8DER)
        guard case let ASN1.ASN1Element.seq(elements: es) = result,
            es.count > 2,
            case let ASN1.ASN1Element.seq(elements: ids) = es[1],
            ids.count > 1,
            case let ASN1.ASN1Element.bytes(data: privateKeyID) = ids[1]
        else {
            throw ECError.failedASN1Decoding
        }
        self.curve = try Curve.objectToCurve(ObjectIdentifier: privateKeyID)
        guard case let ASN1.ASN1Element.bytes(data: privateOctest) = es[2] else {
            throw ECError.failedASN1Decoding
        }
        let (octest, _) = ASN1.toASN1Element(data: privateOctest)
        guard case let ASN1.ASN1Element.seq(elements: seq) = octest,
            seq.count >= 3,
            case let ASN1.ASN1Element.bytes(data: privateKeyData) = seq[1]
        else {
            throw ECError.failedASN1Decoding
        }
        let publicKeyData: Data
        if case let ASN1.ASN1Element.constructed(tag: 1, elem: publicElement) = seq[2],
            case let ASN1.ASN1Element.bytes(data: pubKeyData) = publicElement
        {
            publicKeyData = pubKeyData
        } else if seq.count >= 4,
            case let ASN1.ASN1Element.constructed(tag: 1, elem: publicElement) = seq[3],
            case let ASN1.ASN1Element.bytes(data: pubKeyData) = publicElement
        {
            publicKeyData = pubKeyData
        } else {
            throw ECError.failedASN1Decoding
        }
        let trimmedPubBytes = publicKeyData.drop(while: { $0 == 0x00})
        self.nativeKey =  try ECPrivateKey.bytesToNativeKey(privateKeyData: privateKeyData,
                                                            publicKeyData: trimmedPubBytes,
                                                            curve: curve)
        self.pubKeyBytes = trimmedPubBytes
    }

    /// Initialize an ECPrivateKey from a SEC1 `.der` file data.  
    /// This is equivalent to a PEM String that has had the "-----BEGIN EC PRIVATE KEY-----"
    /// header and footer stripped and been base64 encoded to ASN1 Data.
    /// - Parameter sec1DER: The elliptic curve private key Data.
    /// - Returns: An ECPrivateKey.
    /// - Throws: An ECError if the Data can't be decoded or is not a valid key.
    public init(sec1DER: Data) throws {
        let (result, _) = ASN1.toASN1Element(data: sec1DER)
        guard case let ASN1.ASN1Element.seq(elements: seq) = result,
            seq.count > 3,
            case let ASN1.ASN1Element.constructed(tag: _, elem: objectElement) = seq[2],
            case let ASN1.ASN1Element.bytes(data: objectId) = objectElement,
            case let ASN1.ASN1Element.bytes(data: privateKeyData) = seq[1]
        else {
            throw ECError.failedASN1Decoding
        }
        self.curve = try Curve.objectToCurve(ObjectIdentifier: objectId)
        guard case let ASN1.ASN1Element.constructed(tag: _, elem: publicElement) = seq[3],
            case let ASN1.ASN1Element.bytes(data: publicKeyData) = publicElement
        else {
            throw ECError.failedASN1Decoding
        }
        let trimmedPubBytes = publicKeyData.drop(while: { $0 == 0x00})
        self.nativeKey =  try ECPrivateKey.bytesToNativeKey(privateKeyData: privateKeyData,
                                                            publicKeyData: trimmedPubBytes,
                                                            curve: curve)
        self.pubKeyBytes = trimmedPubBytes
    }
    
    /// Initialize the `ECPublicKey`for this private key by extracting the public key bytes.
    /// - Returns: An ECPublicKey.
    /// - Throws: An ECError if the public key fails to be initialized from this private key.
    public func extractPublicKey() throws -> ECPublicKey {
        let keyHeader: Data
        // Add the ASN1 header for the public key. The bytes have the following structure:
        // SEQUENCE (2 elem)
        //     SEQUENCE (2 elem)
        //         OBJECT IDENTIFIER
        //         OBJECT IDENTIFIER
        //     BIT STRING (This is the `pubKeyBytes` added afterwards)
        if self.curve == .prime256v1 {
            keyHeader = Data(bytes: [0x30, 0x59,
                                     0x30, 0x13,
                                     0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
                                     0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42])
        } else if self.curve == .secp384r1 {
            keyHeader = Data(bytes: [0x30, 0x76,
                                     0x30, 0x10,
                                     0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
                                     0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62])
        } else if self.curve == .secp521r1 {
            keyHeader = Data(bytes: [0x30, 0x81, 0x9B,
                                     0x30, 0x10,
                                     0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
                                     0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23, 0x03, 0x81, 0x86])
        } else {
            throw ECError.unsupportedCurve
        }
        // If we stripped the leading zero earlier, add it back here
        var pubBytes = self.pubKeyBytes
        if pubBytes.startIndex != 0 {
            pubBytes = Data(count: 1) + self.pubKeyBytes
        }
        return try ECPublicKey(der: keyHeader + pubBytes)
    }


    private static func bytesToNativeKey(privateKeyData: Data, publicKeyData: Data, curve: Curve) throws -> NativeKey {
        #if os(Linux)
            let bigNum = BN_new()
            defer {
                BN_free(bigNum)
            }
            privateKeyData.withUnsafeBytes({ (privateKeyBytes: UnsafePointer<UInt8>) -> Void in
                BN_bin2bn(privateKeyBytes, Int32(privateKeyData.count), bigNum)
            })
            let ecKey = EC_KEY_new_by_curve_name(curve.nativeCurve)
            guard EC_KEY_set_private_key(ecKey, bigNum) == 1 else {
                EC_KEY_free(ecKey)
                throw ECError.failedNativeKeyCreation
            }
            return ecKey
        #else
            let keyData = publicKeyData + privateKeyData
            var error: Unmanaged<CFError>? = nil
            guard let secKey = SecKeyCreateWithData(keyData as CFData,
                                                    [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
                                                     kSecAttrKeyClass: kSecAttrKeyClassPrivate] as CFDictionary,
                                                    &error)
            else {
                if let secError = error?.takeRetainedValue() {
                    throw secError
                } else {
                    throw ECError.failedNativeKeyCreation
                }
            }
            return secKey
        #endif
    }
}
