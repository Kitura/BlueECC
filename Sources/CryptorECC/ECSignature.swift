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
import Darwin

#elseif os(Linux)
import OpenSSL
import Glibc
#endif

/// The signature produced by applying Elliptic Curve Digital Signature Algorithm
/// to some `Plaintext` data. It consist of two binary unsigned ints r and s.
@available(OSX 10.12, *)
public struct ECSignature {
    public let r: Data
    public let s: Data
    public let asn1: Data

    public init?(r: Data, s: Data) {
        guard let asn1 = ECSignature.rsSigToASN1(r: r, s: s) else {
            return nil
        }
        self.r = r
        self.s = s
        self.asn1 = asn1
    }
    
    public init?(asn1: Data) {
        self.asn1 = asn1
        guard let (r,s) = ECSignature.asn1ToRSSig(asn1: asn1) else {
            return nil
        }
        self.r = r
        self.s = s
    }

    public init?(base64EncodedString: String) {
        guard let data = Data(base64Encoded: base64EncodedString) else {
            return nil
        }
        let r = data.subdata(in: 0 ..< data.count/2)
        let s = data.subdata(in: data.count/2 ..< data.count)
        if let asn1 = ECSignature.rsSigToASN1(r: r, s: s) {
            self.r = r
            self.s = s
            self.asn1 = asn1
        } else if let (asn1R,asn1S) = ECSignature.asn1ToRSSig(asn1: data) {
            self.r = asn1R
            self.s = asn1S
            self.asn1 = data
        } else {
            return nil
        }
    }

    // Verify the signature using the given public key.
    public func verify(plaintext: Plaintext, using ecPublicKey: ECPublicKey) -> Bool {
        
        #if os(Linux)
            fputs("--Entered Verify--", stderr)
            let signatureBytes = [UInt8](self.asn1)
            let md_ctx = EVP_MD_CTX_new_wrapper()
            let evp_key = EVP_PKEY_new()
            defer {
                fputs("--In Defer--", stderr)
                EVP_MD_CTX_free_wrapper(md_ctx)
            }
            fputs("--Made Wrapper--", stderr)
        
            EVP_PKEY_set1_EC_KEY(evp_key, .make(optional: ecPublicKey.nativeKey))
            var pkey_ctx = EVP_PKEY_CTX_new(evp_key, nil)
            fputs("--Set Keys--", stderr)
            EVP_DigestVerifyInit(md_ctx, &pkey_ctx, .make(optional: ecPublicKey.hashAlgorithm.signingAlgorithm), nil, evp_key)
        fputs("--EVP_DigestVerifyInit--", stderr)
            let _ = plaintext.data.withUnsafeBytes({ (message: UnsafePointer<UInt8>) -> Int32 in
                return EVP_DigestUpdate(md_ctx, message, plaintext.data.count)
            })
        fputs("--EVP_DigestUpdate--", stderr)
        fputs("--self.asn1.count: \(self.asn1.count)--", stderr)
            let rc = self.asn1.withUnsafeBytes({ (sig: UnsafePointer<UInt8>) -> Int32 in
                return EVP_DigestVerifyFinal(md_ctx, sig, self.asn1.count)
            })
        fputs("--SSL_EVP_digestVerifyFinal_wrapper--", stderr)

            return rc == 1
        #else
            // MacOS, iOS ect.
            let hash = ecPublicKey.hashAlgorithm.digest(data: plaintext.data)

            // Memory storage for error from SecKeyVerifySignature
            var error: Unmanaged<CFError>? = nil
            if SecKeyVerifySignature(ecPublicKey.nativeKey,
                                     ecPublicKey.hashAlgorithm.signingAlgorithm,
                                     hash as CFData,
                                     self.asn1 as CFData,
                                     &error) {
                return true
            } else {
                let thrownError = error?.takeRetainedValue()
                print("Failed to verify asnSignature: \(thrownError as Any)")
                return false
            }
        #endif
    }

    static func rsSigToASN1(r: Data, s: Data) -> Data? {
        // Convert r,s signature to ASN1 for SecKeyVerifySignature
        var asnSignature = Data()
        // r value is first 32 bytes
        var rSig =  r
        // If first bit is 1, add a 00 byte to mark it as positive for ASN1
        if rSig[0] == 0 {
            rSig = rSig.advanced(by: 1)
        }
        if rSig[0].leadingZeroBitCount == 0 {
            rSig = Data(count: 1) + rSig
        }
        // r value is last 32 bytes
        var sSig = s
        // If first bit is 1, add a 00 byte to mark it as positive for ASN1
        if sSig[0] == 0 {
            sSig = sSig.advanced(by: 1)
        }
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
        fputs("asnSignature: \(asnSignature.base64EncodedString())", stderr)
        return asnSignature
    }

    static func asn1ToRSSig(asn1: Data) -> (Data, Data)? {
        
         print("asn1 length: \(asn1.count)")
        let signatureLength: Int
        if asn1.count < 96 {
            print("signatureLength: 64")
            signatureLength = 64
        } else if asn1.count < 132 {
            signatureLength = 96
            print("signatureLength: 96")
        } else {
            signatureLength = 132
            print("signatureLength: 132")
        }
        
        // Parse ASN into just r,s data as defined in:
        // https://tools.ietf.org/html/rfc7518#section-3.4
        let (asnSig, _) = ASN1.toASN1Element(data: asn1)
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
        let rExtra = rData.count - signatureLength/2
        if rExtra < 0 {
            trimmedRData = Data(count: 1) + rData
        } else {
            trimmedRData = rData.dropFirst(rExtra)
        }
        let sExtra = sData.count - signatureLength/2
        if sExtra < 0 {
            trimmedSData = Data(count: 1) + sData
        } else {
            trimmedSData = sData.dropFirst(sExtra)
        }
        return (trimmedRData, trimmedSData)
    }
}
