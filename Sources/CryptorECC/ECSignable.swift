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

/// A protocol for signing an instance of some object to generate an `ECSignature`.
@available(OSX 10.12, *)
public protocol ECSignable {
    func sign(with: ECPrivateKey) throws -> ECSignature
}

/// Extension for signing a `String` by converting it to utf8 Data and signing the bytes.
@available(OSX 10.12, *)
extension String: ECSignable {
    public func sign(with: ECPrivateKey) throws -> ECSignature {
        return try Data(self.utf8).sign(with: with)
    }
}

/// Extension for signing `Data` with an `ECPrivateKey` and the algorithm determined by the key's curve.
@available(OSX 10.12, *)
extension Data: ECSignable {
    /// Sign the plaintext data using the provided `ECPrivateKey`.
    /// The signing algorithm used is determined based on the private key's elliptic curve.
    /// - Parameter ecPrivateKey: The Elliptic curve private key.
    /// - Returns: An ECSignature or nil on failure.
    public func sign(with ecPrivateKey: ECPrivateKey) throws -> ECSignature {
        let signature: Data
        #if os(Linux)
        let md_ctx = EVP_MD_CTX_new_wrapper()
        let evp_key = EVP_PKEY_new()
        guard EVP_PKEY_set1_EC_KEY(evp_key, .make(optional: ecPrivateKey.nativeKey)) == 1 else {
            throw ECError(reason: "Failed to set OpenSSL key as native key")
        }
        var pkey_ctx = EVP_PKEY_CTX_new(evp_key, nil)
        defer {
            EVP_PKEY_free(evp_key)
            EVP_MD_CTX_free_wrapper(md_ctx)
        }
        
        EVP_DigestSignInit(md_ctx, &pkey_ctx, .make(optional: ecPrivateKey.hashAlgorithm.signingAlgorithm), nil, evp_key)
        
        _ = self.withUnsafeBytes({ (message: UnsafePointer<UInt8>) -> Int32 in
            return EVP_DigestUpdate(md_ctx, message, self.count)
        })
        
        var sig_len: Int = 0
        EVP_DigestSignFinal(md_ctx, nil, &sig_len)
        let sig = UnsafeMutablePointer<UInt8>.allocate(capacity: sig_len)
        defer {
            #if swift(>=4.1)
            sig.deallocate()
            #else
            sig.deallocate(capacity: sig_len)
            #endif
        }
        let _ = EVP_DigestSignFinal(md_ctx, sig, &sig_len)
        signature = Data(bytes: sig, count: sig_len)
        #else
        // MacOS, iOS ect.
        let hash = ecPrivateKey.hashAlgorithm.digest(data: self)
        
        // Memory storage for error from SecKeyCreateSignature
        var error: Unmanaged<CFError>? = nil
        
        // cfSignature is CFData that is ANS1 encoded as a sequence of two 32 Byte UInt (r and s)
        guard let cfSignature = SecKeyCreateSignature(ecPrivateKey.nativeKey, ecPrivateKey.hashAlgorithm.signingAlgorithm, hash as CFData, &error)  else {
            if let thrownError = error?.takeRetainedValue() {
                throw thrownError
            } else {
                throw ECError(reason: "SecKeyCreateSignature failed and provided no error")
            }
        }
        signature = cfSignature as Data
        #endif
        return try ECSignature(asn1: signature)
    }
}
