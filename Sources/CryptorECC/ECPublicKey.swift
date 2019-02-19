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

/// A class representing an elliptic curve public key.
@available(OSX 10.12, *)
public class ECPublicKey {
    #if os(Linux)
    public typealias NativeKey = OpaquePointer?
    #else
    public typealias NativeKey = SecKey
    #endif
    let nativeKey: NativeKey
    let hashAlgorithm: HashAlgorithm

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
     let pemKey = ECPublicKey(pemKey: publicKeyString)
     ```
     */
    public init?(pemKey: String) {
        guard let asn1Key = ASN1.pemToASN1(key: pemKey) else {
            return nil
        }
        let (result, _) = ASN1.toASN1Element(data: asn1Key)
        guard case let ASN1.ASN1Element.seq(elements: seq) = result,
            seq.count > 1,
            case let ASN1.ASN1Element.seq(elements: ids) = seq[0],
            ids.count > 1,
            case let ASN1.ASN1Element.bytes(data: privateKeyID) = ids[1],
            let hashAlgorithm = HashAlgorithm.objectToHashAlg(ObjectIdentifier: privateKeyID),
            case let ASN1.ASN1Element.bytes(data: publicKeyData) = seq[1]
        else {
                return nil
        }
        self.hashAlgorithm = hashAlgorithm
        #if os(Linux)
            let bigNum = BN_new()
            let publicKeyBytes = [UInt8](publicKeyData)
            BN_bin2bn(publicKeyBytes, Int32(publicKeyBytes.count), bigNum)
            let ecKey = EC_KEY_new_by_curve_name(hashAlgorithm.curve)
            let ecGroup = EC_KEY_get0_group(ecKey)
            let ecPoint = EC_POINT_new(ecGroup)
            EC_POINT_bn2point(ecGroup, bigNum, ecPoint, nil)
            EC_KEY_set_public_key(ecKey, ecPoint)
            BN_free(bigNum)
            EC_POINT_free(ecPoint)
            self.nativeKey = ecKey
        #else
            let keyData = publicKeyData.drop(while: { $0 == 0x00})
            var error: Unmanaged<CFError>? = nil
            guard let secKey = SecKeyCreateWithData(keyData as CFData,
                                                    [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPublic, kSecAttrKeySizeInBits: 256] as CFDictionary, &error)
                else {
                    let thrownError = error?.takeRetainedValue()
                    print(thrownError as Any)
                    return nil
            }
            self.nativeKey = secKey
        #endif
    }
    
    #if os(Linux)
    deinit {
        EC_KEY_free(self.nativeKey)
    }
    #endif
}
