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

@available(OSX 10.12, *)
public struct Plaintext {
    public let data: Data
    
    public init(data: Data) {
        self.data = data
    }
    
    public init?(string: String, encoding: String.Encoding = .utf8) {
        guard let data = string.data(using: encoding) else {
            return nil
        }
        self.data = data
    }
    
    public func signUsing(ecPrivateKey: ECPrivateKey) -> Signature? {
        
        let signature: Data
        let hash = ecPrivateKey.hashAlgorithm.digest(data: data)
        
        #if os(Linux)
            let maxSigLength = Int(ECDSA_size(ecPrivateKey.nativeKey))
            let signedBytes = UnsafeMutablePointer<UInt8>.allocate(capacity: maxSigLength)
            let signedBytesLength = UnsafeMutablePointer<UInt32>.allocate(capacity: 1)
            defer {
                #if swift(>=4.1)
                signedBytes.deallocate()
                signedBytesLength.deallocate()
                #else
                signedBytes.deallocate(capacity: maxSigLength)
                signedBytesLength.deallocate(capacity: 1)
                #endif
            }
            ECDSA_sign(0, [UInt8](hash), Int32(hash.count), signedBytes, signedBytesLength, ecPrivateKey.nativeKey)
            signature = Data(bytes: signedBytes, count: Int(signedBytesLength.pointee))
        #else
            // MacOS, iOS ect.
        
            // Memory storage for error from SecKeyCreateSignature
            var error: Unmanaged<CFError>? = nil
        
            // cfSignature is CFData that is ANS1 encoded as a sequence of two 32 Byte UInt (r and s)
            guard let cfSignature = SecKeyCreateSignature(ecPrivateKey.nativeKey, ecPrivateKey.hashAlgorithm.signingAlgorithm, hash as CFData, &error)  else {
                let thrownError = error?.takeRetainedValue()
                print("cfSignature failed: \(thrownError as Any)")
                return nil
            }
            signature = cfSignature as Data
        #endif
        // Parse ASN into just r,s data as defined in:
        // https://tools.ietf.org/html/rfc7518#section-3.4
        let (asnSig, _) = ASN1.toASN1Element(data: signature)
        guard case let ASN1.ASN1Element.seq(elements: seq) = asnSig,
            seq.count >= 2,
            case let ASN1.ASN1Element.bytes(data: rData) = seq[0],
            case let ASN1.ASN1Element.bytes(data: sData) = seq[1]
            else {
                print("Failed to decode cfSignature ASN1")
                return nil
        }
        // ASN adds 00 bytes in front of negative Int to mark it as positive.
        // These must be removed to make r,a a valid EC signature
        let trimmedRData: Data
        let trimmedSData: Data
        let rExtra = rData.count - ecPrivateKey.hashAlgorithm.signatureLength/2
        if rExtra < 0 {
            trimmedRData = Data(count: 1) + rData
        } else {
            trimmedRData = rData.dropFirst(rExtra)
        }
        let sExtra = sData.count - ecPrivateKey.hashAlgorithm.signatureLength/2
        if sExtra < 0 {
            trimmedSData = Data(count: 1) + sData
        } else {
            trimmedSData = sData.dropFirst(sExtra)
        }
        return Signature(data: trimmedRData + trimmedSData)
    }
}
