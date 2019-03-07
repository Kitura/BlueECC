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
    /// A String description of the curve this key was generated from.
    public let curveId: String
    
    /// The `EllipticCurve` this key was generated from.
    public let curve: EllipticCurve
    
    #if os(Linux)
        typealias NativeKey = OpaquePointer?
        deinit { EC_KEY_free(.make(optional: self.nativeKey)) }
    #else
        typealias NativeKey = SecKey
    #endif
    let nativeKey: NativeKey
    let pubKeyBytes: Data
    private var stripped: Bool = false


    /**
     Initialise an new ECPrivate key from a supported `Curve`
     ### Usage Example:
     ```swift
     let key = try ECPrivateKey(for: .prime256v1)
     ```
     - Parameter for curve: The elliptic curve that is used to generate the key.
     - Returns: An ECPrivateKey.
     - Throws: An ECError if the key fails to be created.
    */
    public init(for curve: EllipticCurve) throws {
        self.curve = curve
        self.curveId = curve.description
        self.stripped = true
        #if os(Linux)
            let ec_key = EC_KEY_new_by_curve_name(curve.nativeCurve)
            EC_KEY_generate_key(ec_key)
            self.nativeKey = ec_key
            let pub_bn_ctx = BN_CTX_new()
            BN_CTX_start(pub_bn_ctx)
            let pub = EC_KEY_get0_public_key(ec_key)
            let ec_group = EC_KEY_get0_group(ec_key)
            let pub_bn = BN_new()
            EC_POINT_point2bn(ec_group, pub, POINT_CONVERSION_UNCOMPRESSED, pub_bn, pub_bn_ctx)
            let pubk = UnsafeMutablePointer<UInt8>.allocate(capacity: curve.keySize)
            BN_bn2bin(pub_bn, pubk)
            self.pubKeyBytes = Data(bytes: pubk, count: curve.keySize)
            defer {
                BN_CTX_end(pub_bn_ctx)
                BN_CTX_free(pub_bn_ctx)
                BN_clear_free(pub_bn)
                #if swift(>=4.1)
                pubk.deallocate()
                #else
                pubk.deallocate(capacity: curve.keySize)
                #endif
            }
        #else
            let kAsymmetricCryptoManagerKeyType = kSecAttrKeyTypeECSECPrimeRandom
            let kAsymmetricCryptoManagerKeySize: Int
            if curve == .prime256v1 {
                kAsymmetricCryptoManagerKeySize = 256
            } else if curve == .secp384r1 {
                kAsymmetricCryptoManagerKeySize = 384
            } else {
                kAsymmetricCryptoManagerKeySize = 521
            }
            // parameters
            let parameters: [String: AnyObject] = [
                kSecAttrKeyType as String:          kAsymmetricCryptoManagerKeyType,
                kSecAttrKeySizeInBits as String:    kAsymmetricCryptoManagerKeySize as AnyObject,
                ]
            var pubKey, privKey: SecKey?
            let status = SecKeyGeneratePair(parameters as CFDictionary, &pubKey, &privKey)
            guard status == 0, let newPubKey = pubKey, let newPrivKey = privKey else {
                throw ECError.failedNativeKeyCreation
            }
            var error: Unmanaged<CFError>? = nil
            guard let pubBytes = SecKeyCopyExternalRepresentation(newPubKey, &error) else {
                guard let error = error?.takeRetainedValue() else {
                    throw ECError.failedNativeKeyCreation
                }
                throw error
            }
            self.pubKeyBytes = pubBytes as Data
            self.nativeKey = newPrivKey
        #endif
    }
    
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
        let (der, header) = try ECPrivateKey.pemToDERData(key: key)
        if header == "BEGINECPRIVATEKEY" {
            try self.init(sec1DER: der)
        } else if header == "BEGINPRIVATEKEY" {
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
        self.curve = try EllipticCurve.objectToCurve(ObjectIdentifier: privateKeyID)
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
        if trimmedPubBytes.count != publicKeyData.count {
            stripped = true
        }
        self.nativeKey =  try ECPrivateKey.bytesToNativeKey(privateKeyData: privateKeyData,
                                                            publicKeyData: trimmedPubBytes,
                                                            curve: curve)
        self.pubKeyBytes = trimmedPubBytes
        self.curveId = curve.description
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
        self.curve = try EllipticCurve.objectToCurve(ObjectIdentifier: objectId)
        guard case let ASN1.ASN1Element.constructed(tag: _, elem: publicElement) = seq[3],
            case let ASN1.ASN1Element.bytes(data: publicKeyData) = publicElement
        else {
            throw ECError.failedASN1Decoding
        }
        let trimmedPubBytes = publicKeyData.drop(while: { $0 == 0x00})
        if trimmedPubBytes.count != publicKeyData.count {
            stripped = true
        }
        self.nativeKey =  try ECPrivateKey.bytesToNativeKey(privateKeyData: privateKeyData,
                                                            publicKeyData: trimmedPubBytes,
                                                            curve: curve)
        self.pubKeyBytes = trimmedPubBytes
        self.curveId = curve.description
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
        if stripped {
            pubBytes = Data(count: 1) + self.pubKeyBytes
        }
        return try ECPublicKey(der: keyHeader + pubBytes)
    }
    
    /// Decode this ECPrivateKey to it's PEM format
    public func decodeToPEM() throws -> String {
        #if os(Linux)
            let pemBio = BIO_new(BIO_s_mem())
            defer { BIO_free(pemBio) }
            PEM_write_bio_ECPrivateKey(pemBio, nativeKey, nil, nil, 0, nil, nil)
            let pemSize: Int32
            if curve == .prime256v1 {
                pemSize = 555
            } else if curve == .secp384r1 {
                pemSize = 750
            } else {
                pemSize = 975
            }
            let pem = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(pemSize))
            BIO_read(pemBio, pem, pemSize)
            let pemData = Data(bytes: pem, count: Int(pemSize))
            #if swift(>=4.1)
            pem.deallocate()
            #else
            pem.deallocate(capacity: Int(pemSize))
            #endif
            guard let pemString = String(data: pemData, encoding: .utf8) else {
                throw ECError.failedUTF8Decoding
            }
            // The PEM String returned by OpenSSL contains lots of empty unused fields.
            // We just pull out the public and private key that we are interested in.
            let (der, _) = try ECPrivateKey.pemToDERData(key: pemString)
            let (result, _) = ASN1.toASN1Element(data: der)
            guard case let ASN1.ASN1Element.seq(elements: seq) = result,
                seq.count > 3,
                case let ASN1.ASN1Element.bytes(data: privateKeyData) = seq[1]
                else {
                    throw ECError.failedASN1Decoding
            }
            guard case let ASN1.ASN1Element.constructed(tag: _, elem: publicElement) = seq[3],
                case let ASN1.ASN1Element.bytes(data: publicKeyData) = publicElement
                else {
                    throw ECError.failedASN1Decoding
            }
        #else
            var error: Unmanaged<CFError>? = nil
        /*
         From Apple docs:
         For an elliptic curve private key, `SecKeyCopyExternalRepresentation` output is formatted as the public key concatenated with the big endian encoding of the secret scalar, or 04 || X || Y || K.
         */
            guard let keyBytes = SecKeyCopyExternalRepresentation(nativeKey, &error) else {
                guard let error = error?.takeRetainedValue() else {
                    throw ECError.failedNativeKeyCreation
                }
                throw error
            }
            let keyData = keyBytes as Data
            let privateKeyData = keyData.dropFirst(curve.keySize)
            let publicKeyData = Data(bytes: [0x00]) + keyData.dropLast(keyData.count - curve.keySize)
        #endif
        var keyHeader: Data
        // Add the ASN1 header for the private key. The bytes have the following structure:
        // SEQUENCE (4 elem)
        //     INTEGER 1
        //     OCTET STRING (32 byte) (This is the `privateKeyBytes`)
        //     [0] (1 elem)
        //         OBJECT IDENTIFIER
        //     [1] (1 elem)
        //         BIT STRING (This is the `pubKeyBytes`)
        if self.curve == .prime256v1 {
            keyHeader = Data(bytes: [0x30, 0x77,
                                     0x02, 0x01, 0x01,
                                     0x04, 0x20])
            keyHeader += privateKeyData
            keyHeader += Data(bytes: [0xA0,
                                      0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
                                      0xA1,
                                      0x44, 0x03, 0x42])
            keyHeader += publicKeyData
        } else if self.curve == .secp384r1 {
            keyHeader = Data(bytes: [0x30, 0x81, 0xA4,
                                     0x02, 0x01, 0x01,
                                     0x04, 0x30])
            keyHeader += privateKeyData
            keyHeader += Data(bytes: [0xA0,
                                      0x07, 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22,
                                      0xA1,
                                      0x64, 0x03, 0x62])
            keyHeader += publicKeyData
        } else if self.curve == .secp521r1 {
            keyHeader = Data(bytes: [0x30, 0x81, 0xDC,
                                     0x02, 0x01, 0x01,
                                     0x04, 0x42])
            keyHeader += privateKeyData
            keyHeader += Data(bytes: [0xA0,
                                      0x07, 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23,
                                      0xA1,
                                      0x81, 0x89, 0x03, 0x81, 0x86])
            keyHeader += publicKeyData
        } else {
            throw ECError.unsupportedCurve
        }
        return ECPrivateKey.derToPrivatePEM(derData: keyHeader)
    }

    private static func bytesToNativeKey(privateKeyData: Data, publicKeyData: Data, curve: EllipticCurve) throws -> NativeKey {
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
    
    private static func derToPrivatePEM(derData: Data) -> String {
        // First convert the DER data to a base64 string...
        let base64String = derData.base64EncodedString()
        // Split the string into strings of length 65...
        let lines = base64String.split(to: 64)
        // Join those lines with a new line...
        let joinedLines = lines.joined(separator: "\n")
        return "-----BEGIN EC PRIVATE KEY-----\n" + joinedLines + "\n-----END EC PRIVATE KEY-----"
    }
    
    private static func pemToDERData(key: String) throws  -> (Data, String) {
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
        return (der, pemComponents[1])
    }
}
