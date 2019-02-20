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

/// A protocol for decrypting an instance of some object to generate some plaintext data.
@available(OSX 10.12, *)
public protocol ECDecryptable {
    /// Decrypt the object using ECIES and produce some plaintext `Data`.
    func decrypt(with: ECPrivateKey) throws -> Data
    
    /// Decrypt the object using ECIES and produce some plaintext `String`.
    func decryptToString(with: ECPrivateKey) throws -> String
}

/// Extension for signing a `String` by converting it to utf8 Data and signing the bytes.
@available(OSX 10.12, *)
extension String: ECDecryptable {

    /// Convert the String to Base64Encoded `Data` and decrypt it using the `ECPrivateKey`.
    /// - Parameter ecPrivateKey: The Elliptic curve private key.
    /// - Returns: An ECSignature or nil on failure.
    public func decrypt(with key: ECPrivateKey) throws -> Data {
        guard let encrypted = Data(base64Encoded: self) else {
            throw ECError.failedBase64Encoding
        }
        return try encrypted.decrypt(with: key)
    }
    
    /// Convert the String to Base64Encoded `Data` and decrypt it using the `ECPrivateKey`
    /// and decode the plaintext to a UTF8 String.
    public func decryptToString(with key: ECPrivateKey) throws -> String {
        guard let encrypted = Data(base64Encoded: self) else {
            throw ECError.failedBase64Encoding
        }
        return try encrypted.decryptToString(with: key)
    }
}

/// Extension for decrypting `Data` with an `ECPrivateKey` and the algorithm determined by the key's curve.
@available(OSX 10.12, *)
extension Data: ECDecryptable {
    
    /// Decrypt the Data using the `ECPrivateKey` and decode the plaintext to a UTF8 String.
    public func decryptToString(with key: ECPrivateKey) throws -> String {
        let decryptedData = try self.decrypt(with: key)
        guard let decryptedString = String(data: decryptedData, encoding: .utf8) else {
            throw ECError.failedUTF8Decoding
        }
        return decryptedString
    }
    
    /// Decrypt the encrypted data using the provided `ECPrivateKey`.
    /// The signing algorithm used is determined based on the private key's elliptic curve.
    /// - Parameter ecPrivateKey: The Elliptic curve private key.
    /// - Returns: An ECSignature or nil on failure.
    public func decrypt(with key: ECPrivateKey) throws -> Data {
        #if os(Linux)
        // Not implemented
        throw ECError.failedBase64Encoding
        #else
        var error: Unmanaged<CFError>? = nil
        guard let eData = SecKeyCreateDecryptedData(key.nativeKey,
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
