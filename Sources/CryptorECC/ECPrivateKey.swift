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

/// A class representing an Elliptic curve private key.
@available(OSX 10.12, *)
public class ECPrivateKey {
    #if os(Linux)
    public typealias NativeKey = OpaquePointer?
    #else
    public typealias NativeKey = SecKey
    #endif
    let nativeKey: NativeKey
    let hashAlgorithm: HashAlgorithm
    
    /**
     Initialize an ECPrivateKey from a `.p8` file format.
     ### Usage Example: ###
     ```swift
     let privateKeyString = """
     -----BEGIN PRIVATE KEY-----
     MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg2sD+kukkA8GZUpmm
     jRa4fJ9Xa/JnIG4Hpi7tNO66+OGgCgYIKoZIzj0DAQehRANCAATZp0yt0btpR9kf
     ntp4oUUzTV0+eTELXxJxFvhnqmgwGAm1iVW132XLrdRG/ntlbQ1yzUuJkHtYBNve
     y+77Vzsd
     -----END PRIVATE KEY-----
     """
     let p8Key = ECPrivateKey(p8Key: privateKeyString)
     ```
     */
    public init?(p8Key: String) {
        guard let asn1Key = ASN1.pemToASN1(key: p8Key) else {
            return nil
        }
        let (result, _) = ASN1.toASN1Element(data: asn1Key)
        
        guard case let ASN1.ASN1Element.seq(elements: es) = result,
            es.count > 2,
            case let ASN1.ASN1Element.seq(elements: ids) = es[1],
            ids.count > 1,
            case let ASN1.ASN1Element.bytes(data: privateKeyID) = ids[1],
            let hashAlgorithm = HashAlgorithm.objectToHashAlg(ObjectIdentifier: privateKeyID) else {
                return nil
        }
        self.hashAlgorithm = hashAlgorithm
        guard case let ASN1.ASN1Element.bytes(data: privateOctest) = es[2] else {
            return nil
        }
        let (octest, _) = ASN1.toASN1Element(data: privateOctest)
        guard case let ASN1.ASN1Element.seq(elements: seq) = octest,
            seq.count >= 3,
            case let ASN1.ASN1Element.bytes(data: privateKeyData) = seq[1] else {
                return nil
        }
        #if os(Linux)
        self.nativeKey =  ECPrivateKey.bytesToNativeKey(privateKeyData: privateKeyData, hashAlgorithm: hashAlgorithm)
        #else
        let publicKeyData: Data
            if case let ASN1.ASN1Element.constructed(tag: 1, elem: publicElement) = seq[2],
                case let ASN1.ASN1Element.bytes(data: pubKeyData) = publicElement {
                publicKeyData = pubKeyData
            }
            else if seq.count >= 4,
                case let ASN1.ASN1Element.constructed(tag: 1, elem: publicElement) = seq[3],
                case let ASN1.ASN1Element.bytes(data: pubKeyData) = publicElement {
                publicKeyData = pubKeyData
            } else {
                return nil
            }
            let keyData = publicKeyData.drop(while: { $0 == 0x00}) + privateKeyData
            var error: Unmanaged<CFError>? = nil
            guard let secKey = SecKeyCreateWithData(keyData as CFData,
                                                    [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPrivate, kSecAttrKeySizeInBits: 256] as CFDictionary, &error)
                else {
                    let thrownError = error?.takeRetainedValue()
                    print(thrownError as Any)
                    return nil
            }
        
            self.nativeKey = secKey
        #endif
    }
    
    /**
     Initialize an ECPrivateKey from a `.pem` file format.
     ### Usage Example: ###
     ```swift
     let privateKeyString = """
     -----BEGIN EC PRIVATE KEY-----
     MHcCAQEEIJX+87WJ7Gh19sohyZnhxZeXYNOcuGv4Q+8MLge4UkaZoAoGCCqGSM49
     AwEHoUQDQgAEikc5m6C2xtDWeeAeT18WElO37zvFOz8p4kAlhvgIHN23XIClNESg
     KVmLgSSq2asqiwdrU5YHbcHFkgdABM1SPA==
     -----END EC PRIVATE KEY-----
     """
     let pemKey = ECPrivateKey(pemKey: privateKeyString)
     ```
     */
    public init?(pemKey: String) {
        guard let asn1Key = ASN1.pemToASN1(key: pemKey) else {
            return nil
        }
        let (result, _) = ASN1.toASN1Element(data: asn1Key)
        guard case let ASN1.ASN1Element.seq(elements: seq) = result,
            seq.count > 3,
            case let ASN1.ASN1Element.constructed(tag: _, elem: objectElement) = seq[2],
            case let ASN1.ASN1Element.bytes(data: objectId) = objectElement,
            case let ASN1.ASN1Element.bytes(data: privateKeyData) = seq[1],
            let hashAlgorithm = HashAlgorithm.objectToHashAlg(ObjectIdentifier: objectId) else {
                return nil
        }
        self.hashAlgorithm = hashAlgorithm
        
        #if os(Linux)
            self.nativeKey =  ECPrivateKey.bytesToNativeKey(privateKeyData: privateKeyData, hashAlgorithm: hashAlgorithm)
        #else
            guard case let ASN1.ASN1Element.constructed(tag: _, elem: publicElement) = seq[3],
                case let ASN1.ASN1Element.bytes(data: publicKeyData) = publicElement else {
                    return nil
            }
            let keyData = publicKeyData.drop(while: { $0 == 0x00}) + privateKeyData
            var error: Unmanaged<CFError>? = nil
            guard let secKey = SecKeyCreateWithData(keyData as CFData,
                                                    [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPrivate, kSecAttrKeySizeInBits: 256] as CFDictionary, &error)
                else {
                    let thrownError = error?.takeRetainedValue()
                    print(thrownError as Any)
                    return nil
            }
            self.nativeKey = secKey
        #endif
    }

    #if os(Linux)
    private static func bytesToNativeKey(privateKeyData: Data, hashAlgorithm: HashAlgorithm) -> OpaquePointer? {
        let bigNum = BN_new()
        let privateKeyBytes = [UInt8](privateKeyData)
        BN_bin2bn(privateKeyBytes, Int32(privateKeyBytes.count), bigNum)
        let ecKey = EC_KEY_new_by_curve_name(hashAlgorithm.curve)
        EC_KEY_set_private_key(ecKey, bigNum)
        BN_free(bigNum)
        return ecKey
    }
    
    deinit {
        EC_KEY_free(self.nativeKey)
    }
    #endif
}
