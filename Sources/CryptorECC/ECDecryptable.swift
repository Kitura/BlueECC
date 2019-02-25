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
@available(OSX 10.13, *)
public protocol ECDecryptable {
    /// Decrypt the object using ECIES and produce some plaintext `Data`.
    func decrypt(with: ECPrivateKey) throws -> Data
    
    /// Decrypt the object using ECIES and produce some plaintext `String`.
    func decryptToString(with: ECPrivateKey) throws -> String
}

/// Extension for signing a `String` by converting it to utf8 Data and signing the bytes.
@available(OSX 10.13, *)
extension String: ECDecryptable {

    /// Convert the String to Base64Encoded `Data` and decrypt it using the `ECPrivateKey`.
    /// - Parameter ecPrivateKey: The Elliptic curve private key.
    /// - Returns: An ECSignature or nil on failure.
    @available(OSX 10.13, *)
    public func decrypt(with key: ECPrivateKey) throws -> Data {
        guard let encrypted = Data(base64Encoded: self) else {
            throw ECError.failedBase64Encoding
        }
        return try encrypted.decrypt(with: key)
    }
    
    /// Convert the String to Base64Encoded `Data` and decrypt it using the `ECPrivateKey`
    /// and decode the plaintext to a UTF8 String.
    @available(OSX 10.13, *)
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
    @available(OSX 10.13, *)
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
    @available(OSX 10.13, *)
    public func decrypt(with key: ECPrivateKey) throws -> Data {
        #if os(Linux)
        // Initialize the decryption context.
        let rsaDecryptCtx = EVP_CIPHER_CTX_new()
        EVP_CIPHER_CTX_init_wrapper(rsaDecryptCtx)
        
        let tagLength = 16
        let encKeyLength = key.algorithm.keySize
        let encryptedDataLength = Int(self.count) - encKeyLength - tagLength
        // Extract encryptedAESKey, encryptedData, GCM tag from data
        let encryptedKey = self.subdata(in: 0..<encKeyLength)
        let encryptedData = self.subdata(in: encKeyLength..<encKeyLength+encryptedDataLength)
        var tagData = self.subdata(in: encKeyLength+encryptedDataLength..<self.count)
        // Allocate memory for decryption
        let ec_group = EC_KEY_get0_group(key.nativeKey)
        let skey_len = Int((EC_GROUP_get_degree(ec_group) + 7) / 8)
        let symKey = UnsafeMutablePointer<UInt8>.allocate(capacity: skey_len)
        let decrypted = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(encryptedData.count + 16))
        defer {
            // On completion deallocate the memory
            EVP_CIPHER_CTX_free_wrapper(rsaDecryptCtx)
            #if swift(>=4.1)
            symKey.deallocate()
            decrypted.deallocate()
            #else
            symKey.deallocate(capacity: skey_len)
            decrypted.deallocate(capacity: Int(encryptedData.count + 16))
            #endif
        }

        // Get public key point from key
        let pubk_point = EC_POINT_new(ec_group)
        let pubk_bn = encryptedKey.withUnsafeBytes({ (pubk: UnsafePointer<UInt8>) -> UnsafeMutablePointer<BIGNUM> in
            return BN_bin2bn(pubk, Int32(encryptedKey.count), nil)
        })
        let pubk_bn_ctx = BN_CTX_new()
        BN_CTX_start(pubk_bn_ctx)
        EC_POINT_bn2point(ec_group, pubk_bn, pubk_point, pubk_bn_ctx)
        BN_CTX_end(pubk_bn_ctx)
        BN_CTX_free(pubk_bn_ctx)
        BN_clear_free(pubk_bn)

        // calculate symmetric key
        ECDH_compute_key(symKey, skey_len, pubk_point, key.nativeKey, nil)
        // processedLen is the number of bytes that each EVP_DecryptUpdate/EVP_DecryptFinal decrypts.
        // The sum of processedLen is the total size of the decrypted message (decMsgLen)
        var processedLen: Int32 = 0
        var decMsgLen: Int32 = 0
        
        // get aes key and iv using ANSI x9.63 Key Derivation Function
        let symKeyData = Data(bytes: symKey, count: skey_len)
        let counterData = Data(bytes: [0x00, 0x00, 0x00, 0x01])
        let preHashKey = symKeyData + counterData + encryptedKey
        let hashedKey = key.algorithm.digest(data: preHashKey)
        let aesKey = [UInt8](hashedKey.subdata(in: 0 ..< 16))
        let iv = [UInt8](hashedKey.subdata(in: 16 ..< 32))
        
        // Set the IV length to be 16 bytes.
        // Set the envelope decryption algorithm as 128 bit AES-GCM.
        guard EVP_DecryptInit_ex(rsaDecryptCtx, EVP_aes_128_gcm(), nil, nil, nil) == 1 else {
            throw ECError.failedDecryptionAlgorithm
        }
        guard EVP_CIPHER_CTX_ctrl(rsaDecryptCtx, EVP_CTRL_GCM_SET_IVLEN, 16, nil) == 1,
        // Set the AES key to be 16 bytes.
        EVP_CIPHER_CTX_set_key_length(rsaDecryptCtx, 16) == 1
        else {
            throw ECError.failedDecryptionAlgorithm
        }
        
        // Set the envelope decryption context AES key and IV.
        guard EVP_DecryptInit_ex(rsaDecryptCtx, nil, nil, aesKey, iv) == 1 else {
            throw ECError.failedDecryptionAlgorithm
        }
        
        // Decrypt the encrypted data using the symmetric key.
        guard encryptedData.withUnsafeBytes({ (enc: UnsafePointer<UInt8>) -> Int32 in
            return EVP_DecryptUpdate(rsaDecryptCtx, decrypted, &processedLen, enc, Int32(encryptedData.count))
        }) != 0 else {
            throw ECError.failedDecryptionAlgorithm
        }
        decMsgLen += processedLen
        // Verify the provided GCM tag.
        guard tagData.withUnsafeMutableBytes({ (tag: UnsafeMutablePointer<UInt8>) -> Int32 in
            return EVP_CIPHER_CTX_ctrl(rsaDecryptCtx, EVP_CTRL_GCM_SET_TAG, 16, tag)
        }) == 1
        else {
            throw ECError.failedDecryptionAlgorithm
        }
        guard EVP_DecryptFinal_ex(rsaDecryptCtx, decrypted.advanced(by: Int(decMsgLen)), &processedLen) == 1 else {
            throw ECError.failedDecryptionAlgorithm
        }
        decMsgLen += processedLen
        // return the decrypted plaintext.
        return Data(bytes: decrypted, count: Int(decMsgLen))
        
        #else
        var error: Unmanaged<CFError>? = nil
        guard let eData = SecKeyCreateDecryptedData(key.nativeKey,
                                                    key.algorithm.curve,
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
