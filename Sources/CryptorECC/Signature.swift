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
public struct Signature {
    public let data: Data
    
    public init(data: Data) {
        self.data = data
    }
    
    public init?(base64EncodedString: String) {
        guard let data = Data(base64Encoded: base64EncodedString) else {
            return nil
        }
        self.data = data
    }
    
    // Verify the signature using the given public key.
    public func verify(plaintext: Plaintext, using ecPublicKey: ECPublicKey) -> Bool {
        
        // Signature must be 64 bytes or it is invalid
        guard data.count == ecPublicKey.hashAlgorithm.signatureLength else {
            print("invalid signatureData length: \(data.count)")
            return false
        }
        
        // Convert r,s signature to ASN1 for SecKeyVerifySignature
        var asnSignature = Data()
        // r value is first 32 bytes
        var rSig =  Data(data.dropLast(ecPublicKey.hashAlgorithm.signatureLength/2))
        // If first bit is 1, add a 00 byte to mark it as positive for ASN1
        if rSig[0].leadingZeroBitCount == 0 {
            rSig = Data(count: 1) + rSig
        }
        // r value is last 32 bytes
        var sSig = Data(data.dropFirst(ecPublicKey.hashAlgorithm.signatureLength/2))
        // If first bit is 1, add a 00 byte to mark it as positive for ASN1
        if sSig[0].leadingZeroBitCount == 0 {
            sSig = Data(count: 1) + sSig
        }
        // Count Byte lengths for ASN1 length bytes
        let rLengthByte = UInt8(rSig.count)
        let sLengthByte = UInt8(sSig.count)
        // total bytes is r + s + rLengthByte + sLengthByte byte + Integer marking bytes
        let tLengthByte = rLengthByte + sLengthByte + 4
        // 0x30 means sequence, 0x02 means Integer
        if tLengthByte > 127 {
            asnSignature.append(contentsOf: [0x30, 0x81, tLengthByte])
        } else {
            asnSignature.append(contentsOf: [0x30, tLengthByte])
        }
        asnSignature.append(contentsOf: [0x02, rLengthByte])
        asnSignature.append(rSig)
        asnSignature.append(contentsOf: [0x02, sLengthByte])
        asnSignature.append(sSig)
        
        let hash = ecPublicKey.hashAlgorithm.digest(data: plaintext.data)
        #if os(Linux)
            let signatureBytes = [UInt8](asnSignature)
            let verify = ECDSA_verify(0, [UInt8](hash), Int32(hash.count), signatureBytes, Int32(signatureBytes.count), ecPublicKey.nativeKey)
            return verify == 1
        #else
            // MacOS, iOS ect.
        
            // Memory storage for error from SecKeyVerifySignature
            var error: Unmanaged<CFError>? = nil
            if SecKeyVerifySignature(ecPublicKey.nativeKey,
                                     ecPublicKey.hashAlgorithm.signingAlgorithm,
                                     hash as CFData,
                                     asnSignature as CFData,
                                     &error) {
                return true
            } else {
                let thrownError = error?.takeRetainedValue()
                print("Failed to verify asnSignature: \(thrownError as Any)")
                return false
            }
        #endif
    }
}
