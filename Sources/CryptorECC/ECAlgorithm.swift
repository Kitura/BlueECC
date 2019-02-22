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

// Information about the Elliptic curve algorithm that will be used for signing/verifying.
@available(OSX 10.12, *)
struct ECAlgorithm {
    #if os(Linux)
        typealias CC_LONG = size_t
        let signingAlgorithm: UnsafePointer<EVP_MD>
        let curve: Int32
        let hashEngine: (_ data: UnsafePointer<UInt8>, _ len: CC_LONG, _ md: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8>?
    #else
        let signingAlgorithm: SecKeyAlgorithm
        let hashEngine: (_ data: UnsafeRawPointer?, _ len: CC_LONG, _ md: UnsafeMutablePointer<UInt8>?) -> UnsafeMutablePointer<UInt8>?
    #endif
    let hashLength: CC_LONG

    #if os(Linux)
    /// Secure Hash Algorithm 2 256-bit
    static let sha256 = ECAlgorithm(signingAlgorithm: EVP_sha256(),
                                    curve: NID_X9_62_prime256v1,
                                    hashEngine: SHA256,
                                    hashLength: CC_LONG(SHA256_DIGEST_LENGTH))
    #else
    /// Secure Hash Algorithm 2 256-bit
    static let sha256 = ECAlgorithm(signingAlgorithm: .ecdsaSignatureDigestX962SHA256,
                                    hashEngine: CC_SHA256,
                                    hashLength: CC_LONG(CC_SHA256_DIGEST_LENGTH))
    #endif

    #if os(Linux)
    /// Secure Hash Algorithm 2 384-bit
    static let sha384 = ECAlgorithm(signingAlgorithm: EVP_sha384(),
                                      curve: NID_secp384r1,
                                      hashEngine: SHA384,
                                      hashLength: CC_LONG(SHA384_DIGEST_LENGTH))
    #else
    /// Secure Hash Algorithm 2 384-bit
    static let sha384 = ECAlgorithm(signingAlgorithm: .ecdsaSignatureDigestX962SHA384,
                                    hashEngine: CC_SHA384,
                                    hashLength: CC_LONG(CC_SHA384_DIGEST_LENGTH))
    #endif

    #if os(Linux)
    /// Secure Hash Algorithm 512-bit
    static let sha512 = ECAlgorithm(signingAlgorithm: EVP_sha512(),
                                      curve: NID_secp521r1,
                                      hashEngine: SHA512,
                                      hashLength: CC_LONG(SHA512_DIGEST_LENGTH))
    #else
    /// Secure Hash Algorithm 512-bit
    static let sha512 = ECAlgorithm(signingAlgorithm: .ecdsaSignatureDigestX962SHA512,
                                    hashEngine: CC_SHA512,
                                    hashLength: CC_LONG(CC_SHA512_DIGEST_LENGTH))
    #endif

    // Select the ECAlgorithm based on the object identifier (OID) extracted from the EC key.
    static func objectToHashAlg(ObjectIdentifier: Data) throws -> ECAlgorithm {
        
        if [UInt8](ObjectIdentifier) == [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07] {
            // p-256 (e.g: prime256v1, secp256r1) private key
            return sha256
        } else if [UInt8](ObjectIdentifier) == [0x2B, 0x81, 0x04, 0x00, 0x22] {
            // p-384 (e.g: secp384r1) private key
            return sha384
        } else if [UInt8](ObjectIdentifier) == [0x2B, 0x81, 0x04, 0x00, 0x23] {
            // p-521 (e.g: secp521r1) private key
            return sha512
        } else {
            throw ECError.unsupportedCurve
        }
    }
    
    /// Return a digest of the data based on the hashEngine.
    func digest(data: Data) -> Data {
        
        var hash = [UInt8](repeating: 0, count: Int(self.hashLength))
        data.withUnsafeBytes {
            _ = self.hashEngine($0, CC_LONG(data.count), &hash)
        }
        return Data(bytes: hash)
    }
}
