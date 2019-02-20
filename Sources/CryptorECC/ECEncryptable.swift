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

/// A protocol for encrypting an instance of some object to generate some encrypted data.
@available(OSX 10.12, *)
public protocol ECEncryptable {
    /// Encrypt the object using ECIES and produce some encrypted `Data`.
    func encrypt(with: ECPublicKey) throws -> Data
    
    /// Encrypt the object using ECIES and encode it to a Base64Encoded String.
    func encryptToString(with: ECPublicKey) throws -> String
}

/// Extension for signing a `String` by converting it to utf8 Data and signing the bytes.
@available(OSX 10.12, *)
extension String: ECEncryptable {
    
    /// Encrypt the String using ECIES and encode it to a Base64Encoded String.
    public func encryptToString(with key: ECPublicKey) throws -> String {
        return try Data(self.utf8).encryptToString(with: key)
    }
    
    /// UTF8 encode the String to Data and sign it using the `ECPrivateKey`.
    /// The signing algorithm used is determined based on the private key's elliptic curve.
    /// - Parameter ecPrivateKey: The Elliptic curve private key.
    /// - Returns: An ECSignature or nil on failure.
    public func encrypt(with key: ECPublicKey) throws -> Data {
        return try Data(self.utf8).encrypt(with: key)
    }
}

/// Extension for signing `Data` with an `ECPrivateKey` and the algorithm determined by the key's curve.
@available(OSX 10.12, *)
extension Data: ECEncryptable {
    
    /// Encrypt the Data using ECIES and encode it to a Base64Encoded String.
    public func encryptToString(with key: ECPublicKey) throws -> String {
        let encryptedData = try self.encrypt(with: key)
        return encryptedData.base64EncodedString()
    }
    
    /// Sign the plaintext data using the provided `ECPrivateKey`.
    /// The signing algorithm used is determined based on the private key's elliptic curve.
    /// - Parameter ecPrivateKey: The Elliptic curve private key.
    /// - Returns: An ECSignature or nil on failure.
    public func encrypt(with key: ECPublicKey) throws -> Data {
        #if os(Linux)
            // Not implemented
            throw ECError.failedBase64Encoding
        #else
            var error: Unmanaged<CFError>? = nil
            guard let eData = SecKeyCreateEncryptedData(key.nativeKey,
                                                        SecKeyAlgorithm.eciesEncryptionStandardX963SHA1AESGCM,
                                                        self as CFData,
                                                        &error)
            else {
                guard let error = error?.takeRetainedValue() else {
                    throw ECError.failedEncryptionAlgorithm
                }
                throw error
            }
            
            return eData as Data
        #endif
        
    }
}
