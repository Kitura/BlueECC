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
@available(OSX 10.13, *)
protocol ECSignable {
    /// Sign the object using ECDSA and produce an `ECSignature`.
    func sign(with: ECPrivateKey) throws -> ECSignature
}

/// Extension for signing a `String` by converting it to utf8 Data and signing the bytes.
@available(OSX 10.13, *)
extension String: ECSignable {
    /// UTF8 encode the String to Data and sign it using the `ECPrivateKey`.
    /// The signing algorithm used is determined based on the private key's elliptic curve.
    /// - Parameter with key: The Elliptic curve private key.
    /// - Returns: An ECSignature on failure.
    /// - Throws: An ECError if a valid signature is unable to be created.
    public func sign(with key: ECPrivateKey) throws -> ECSignature {
        return try Data(self.utf8).sign(with: key)
    }
}

/// Extension for signing `Data` with an `ECPrivateKey` and the algorithm determined by the key's curve.
@available(OSX 10.13, *)
extension Data: ECSignable {
    /// Sign the plaintext data using the provided `ECPrivateKey`.
    /// The signing algorithm used is determined based on the private key's elliptic curve.
    /// - Parameter with key: The Elliptic curve private key.
    /// - Returns: An ECSignature on failure.
    /// - Throws: An ECError if a valid signature is unable to be created.
    public func sign(with key: ECPrivateKey) throws -> ECSignature {
        #if os(Linux)
            let md_ctx = EVP_MD_CTX_new_wrapper()
            let evp_key = EVP_PKEY_new()
            guard EVP_PKEY_set1_EC_KEY(evp_key, .make(optional: key.nativeKey)) == 1 else {
                throw ECError.failedNativeKeyCreation
            }
            var pkey_ctx = EVP_PKEY_CTX_new(evp_key, nil)
            defer {
                EVP_PKEY_free(evp_key)
                EVP_MD_CTX_free_wrapper(md_ctx)
            }
        
            guard EVP_DigestSignInit(md_ctx, &pkey_ctx, .make(optional: key.algorithm.signingAlgorithm), nil, evp_key) == 1 else {
                throw ECError.failedEvpInit
            }
        
            guard self.withUnsafeBytes({ (message: UnsafePointer<UInt8>) -> Int32 in
                return EVP_DigestUpdate(md_ctx, message, self.count)
            }) == 1 else {
                throw ECError.failedSigningAlgorithm
            }
        
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
            guard EVP_DigestSignFinal(md_ctx, sig, &sig_len) == 1 else {
                throw ECError.failedSigningAlgorithm
            }
            return try ECSignature(asn1: Data(bytes: sig, count: sig_len))
        #else
            // MacOS, iOS ect.
            let hash = key.algorithm.digest(data: self)
        
            // Memory storage for error from SecKeyCreateSignature
            var error: Unmanaged<CFError>? = nil
            // cfSignature is CFData that is ANS1 encoded as a sequence of two UInts (r and s)
            guard let cfSignature = SecKeyCreateSignature(key.nativeKey,
                                                          key.algorithm.signingAlgorithm,
                                                          hash as CFData,
                                                          &error)
            else {
                if let thrownError = error?.takeRetainedValue() {
                    throw thrownError
                } else {
                    throw ECError.failedSigningAlgorithm
                }
            }
            return try ECSignature(asn1: cfSignature as Data)
        #endif
    }
}
