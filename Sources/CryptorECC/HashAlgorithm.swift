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
public typealias CC_LONG = size_t
#endif

@available(OSX 10.12, *)
struct HashAlgorithm {

    let hashLength: CC_LONG
    let signatureLength: Int
    
    #if os(Linux)
    let signingAlgorithm: UnsafePointer<EVP_MD>
    let curve: Int32
    #else
    let signingAlgorithm: SecKeyAlgorithm
    #endif
    
     #if os(Linux)
    let engine: (_ data: UnsafePointer<UInt8>, _ len: CC_LONG, _ md: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8>?
    #else
    let engine: (_ data: UnsafeRawPointer?, _ len: CC_LONG, _ md: UnsafeMutablePointer<UInt8>?) -> UnsafeMutablePointer<UInt8>?
    #endif

    #if os(Linux)
    /// Secure Hash Algorithm 2 256-bit
    static let sha256 = HashAlgorithm(hashLength: CC_LONG(SHA256_DIGEST_LENGTH),
                                      signatureLength: 64,
                                      signingAlgorithm: EVP_sha256(),
                                      curve: NID_X9_62_prime256v1,
                                      engine: SHA256)
    #else
    /// Secure Hash Algorithm 2 256-bit
    static let sha256 = HashAlgorithm(hashLength: CC_LONG(CC_SHA256_DIGEST_LENGTH),
                                      signatureLength: 64,
                                      signingAlgorithm: .ecdsaSignatureDigestX962SHA256,
                                      engine: CC_SHA256)
    #endif
    
    #if os(Linux)
    /// Secure Hash Algorithm 2 384-bit
    static let sha384 = HashAlgorithm(hashLength: CC_LONG(SHA384_DIGEST_LENGTH),
                                      signatureLength: 96,
                                      signingAlgorithm: EVP_sha384(),
                                      curve: NID_secp384r1,
                                      engine: SHA384)
    #else
    /// Secure Hash Algorithm 2 384-bit
    static let sha384 = HashAlgorithm(hashLength: CC_LONG(CC_SHA384_DIGEST_LENGTH),
                                      signatureLength: 96,
                                      signingAlgorithm: .ecdsaSignatureDigestX962SHA384,
                                      engine: CC_SHA384)
    #endif
    
    #if os(Linux)
    /// Secure Hash Algorithm 512-bit
    static let sha512 = HashAlgorithm(hashLength: CC_LONG(SHA512_DIGEST_LENGTH),
                                      signatureLength: 132,
                                      signingAlgorithm: EVP_sha512(),
                                      curve: NID_secp521r1,
                                      engine: SHA512)
    #else
    /// Secure Hash Algorithm 512-bit
    static let sha512 = HashAlgorithm(hashLength: CC_LONG(CC_SHA512_DIGEST_LENGTH),
                                      signatureLength: 132,
                                      signingAlgorithm: .ecdsaSignatureDigestX962SHA512,
                                      engine: CC_SHA512)
    #endif
    
    
    static func objectToHashAlg(ObjectIdentifier: Data) -> HashAlgorithm? {
        // p-256 (e.g: prime256v1, secp256r1) private key
        if [UInt8](ObjectIdentifier) == [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07] {
            print("Using sha256")
            return sha256
        }
        // p-384 (e.g: secp384r1) private key
        if [UInt8](ObjectIdentifier) == [0x2B, 0x81, 0x04, 0x00, 0x22] {
            print("Using sha384")
            return sha384
        }
        // p-521 (e.g: secp521r1) private key
        if [UInt8](ObjectIdentifier) == [0x2B, 0x81, 0x04, 0x00, 0x23] {
            print("Using sha512")
            return sha512
        }
        return nil
    }
    
    // MARK: Functions
    
    ///
    /// Return a digest of the data based on this alogorithm.
    ///
    /// - Parameters:
    ///        - data:        The data to hash.
    ///
    /// - Returns:                `Data` containing the data in digest form.
    ///
    func digest(data: Data) -> Data {
        
        var hash = [UInt8](repeating: 0, count: Int(self.hashLength))
        
        data.withUnsafeBytes {
            
            _ = self.engine($0, CC_LONG(data.count), &hash)
        }
        
        return Data(bytes: hash)
    }
    
}
