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
        #if os(Linux)
            let md_ctx = EVP_MD_CTX_new_wrapper()
        
            defer {
                EVP_MD_CTX_free_wrapper(md_ctx)
            }
            let evp_key = EVP_PKEY_new()
            let _ = EVP_PKEY_set1_EC_KEY(evp_key, ecPrivateKey.nativeKey)
            var pkey_ctx = EVP_PKEY_CTX_new(evp_key, nil)
            EVP_DigestSignInit(md_ctx, &pkey_ctx, ecPrivateKey.hashAlgorithm.signingAlgorithm, nil, evp_key)
            _ = self.data.withUnsafeBytes({ (message: UnsafePointer<UInt8>) -> Int32 in
                return EVP_DigestUpdate(md_ctx, message, self.data.count)
            })
            var sig_len: Int = 0
            EVP_DigestSignFinal(md_ctx, nil, &sig_len)
            let sig = UnsafeMutablePointer<UInt8>.allocate(capacity: sig_len)
            let _ = EVP_DigestSignFinal(md_ctx, sig, &sig_len)
            signature = Data(bytes: sig, count: sig_len)
        #else
            // MacOS, iOS ect.
            let hash = ecPrivateKey.hashAlgorithm.digest(data: data)

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
