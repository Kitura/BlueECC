import XCTest
@testable import CryptorECC

@available(OSX 10.12, *)
final class CryptorECCTests: XCTestCase {
    static var allTests = [
        ("test_ECDSACycle", test_PemECDSACycle),
        ("test_P8ECDSACycle", test_P8ECDSACycle),
        ("test_PemECDSAVerify", test_PemECDSAVerify),
        ("test_P8ECDSAVerify", test_P8ECDSAVerify),
    ]
    
    let ecPemPrivateKey = """
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJX+87WJ7Gh19sohyZnhxZeXYNOcuGv4Q+8MLge4UkaZoAoGCCqGSM49
AwEHoUQDQgAEikc5m6C2xtDWeeAeT18WElO37zvFOz8p4kAlhvgIHN23XIClNESg
KVmLgSSq2asqiwdrU5YHbcHFkgdABM1SPA==
-----END EC PRIVATE KEY-----
"""
    let ecPemPublicKey = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEikc5m6C2xtDWeeAeT18WElO37zvF
Oz8p4kAlhvgIHN23XIClNESgKVmLgSSq2asqiwdrU5YHbcHFkgdABM1SPA==
-----END PUBLIC KEY-----
"""
    let ecP8PrivateKey = """
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQglf7ztYnsaHX2yiHJ
meHFl5dg05y4a/hD7wwuB7hSRpmhRANCAASKRzmboLbG0NZ54B5PXxYSU7fvO8U7
PyniQCWG+Agc3bdcgKU0RKApWYuBJKrZqyqLB2tTlgdtwcWSB0AEzVI8
-----END PRIVATE KEY-----
"""
    let ecP8PublicKey = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEikc5m6C2xtDWeeAeT18WElO37zvF
Oz8p4kAlhvgIHN23XIClNESgKVmLgSSq2asqiwdrU5YHbcHFkgdABM1SPA==
-----END PUBLIC KEY-----
"""
    let ecPem384PrivateKey = """
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDBQ6YAp5oWCF3EzJdQupQu2dD6BVf7i5QDb9wMoFicaKlnXzH9weMDz
VM/W4pwLAF+gBwYFK4EEACKhZANiAAQGqeXUjuGMqj0w41MLjTFDT7oUoiFLM/Mq
8xVnMX3IJSYDUc7eWIsJHS9VUAtNFt1dHXSxRnhSBv0ct0VxITCv8W42LUutbUg+
EPzehH6ApDeKJSQxwjnwhgr0J06ThCA=
-----END EC PRIVATE KEY-----
"""
    let ecPem384PublicKey = """
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEBqnl1I7hjKo9MONTC40xQ0+6FKIhSzPz
KvMVZzF9yCUmA1HO3liLCR0vVVALTRbdXR10sUZ4Ugb9HLdFcSEwr/FuNi1LrW1I
PhD83oR+gKQ3iiUkMcI58IYK9CdOk4Qg
-----END PUBLIC KEY-----
"""
    
    func test_PemECDSACycle() {
        guard let exampleJWTHeader = try? JSONSerialization.data(withJSONObject: ["alg": "ES256", "typ": "JWT"]),
            let exampleJWTClaims = try? JSONSerialization.data(withJSONObject: ["sub": "1234567890", "admin": true, "iat": 1516239022])
            else {
                return XCTFail("Failed to serialize JWT to JSON")
        }
        
        let unsignedJWT = exampleJWTHeader.base64urlEncodedString() + "." + exampleJWTClaims.base64urlEncodedString()
        guard let unsignedData = unsignedJWT.data(using: .utf8) else {
            return XCTFail("Failed to encode unsignedJWT to utf8")
        }
        
        guard let ecdsaPrivateKey = ECPrivateKey(pemKey: ecPemPrivateKey) else {
            return XCTFail()
        }
        guard let ecdsaPublicKey = ECPublicKey(pemKey: ecPemPublicKey) else {
            return XCTFail()
        }
        let signature = Plaintext(data: unsignedData).signUsing(ecPrivateKey: ecdsaPrivateKey)
        let verified = signature?.verify(plaintext: Plaintext(data: unsignedData), using: ecdsaPublicKey)
        XCTAssert(verified == true)
    }
    
    func test_P8ECDSACycle() {
        guard let exampleJWTHeader = try? JSONSerialization.data(withJSONObject: ["alg": "ES256", "typ": "JWT"]),
            let exampleJWTClaims = try? JSONSerialization.data(withJSONObject: ["sub": "1234567890", "admin": true, "iat": 1516239022])
            else {
                return XCTFail("Failed to serialize JWT to JSON")
        }
        
        let unsignedJWT = exampleJWTHeader.base64urlEncodedString() + "." + exampleJWTClaims.base64urlEncodedString()
        guard let unsignedData = unsignedJWT.data(using: .utf8) else {
            return XCTFail("Failed to encode unsignedJWT to utf8")
        }
        
        guard let ecdsaPrivateKey = ECPrivateKey(p8Key: ecP8PrivateKey) else {
            return XCTFail()
        }
        guard let ecdsaPublicKey = ECPublicKey(pemKey: ecP8PublicKey) else {
            return XCTFail()
        }
        let signature = Plaintext(data: unsignedData).signUsing(ecPrivateKey: ecdsaPrivateKey)
        let verified = signature?.verify(plaintext: Plaintext(data: unsignedData), using: ecdsaPublicKey)
        XCTAssert(verified == true)
    }
    
    func test_PemECDSAVerify() {
        // generated from jwt.io
        guard let JWTDigest =  "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0".data(using: .utf8),
            let JWTSignature = Data(base64urlEncoded: "jGeUQXuf4WLuqhCHOdrIr2alE4JQyKQwkj-GbZIXQIpwrKLymEd41bka2PSIqRAA6H1A2kLuXhzwFw02qQdMhw") else {
                return XCTFail("Failed to create JWT digest")
        }
        
        guard let ecdsaPublicKey = ECPublicKey(pemKey: ecPemPublicKey) else {
            return XCTFail()
        }
        let verified = Signature(data: JWTSignature).verify(plaintext: Plaintext(data: JWTDigest), using: ecdsaPublicKey)
        XCTAssert(verified == true)
    }
    
    func test_P8ECDSAVerify() {
        // generated from jwt.io
        guard let JWTDigest =  "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0".data(using: .utf8),
            let JWTSignature = Data(base64urlEncoded: "faLW3RiQtUG6U71gCrGEBY7AWNfYphygJQKoW8apoB4beX_-GFhkBwkcZATXKIL8UoFLHqmdKK97vO2Nv3OWDA") else {
                return XCTFail("Failed to create JWT digest")
        }
        
        guard let ecdsaPublicKey = ECPublicKey(pemKey: ecPemPublicKey) else {
            return XCTFail()
        }
        
        let verified = Signature(data: JWTSignature).verify(plaintext: Plaintext(data: JWTDigest), using: ecdsaPublicKey)
        XCTAssert(verified == true)
    }
    
    func test_Pem384ECDSACycle() {
        guard let exampleJWTHeader = try? JSONSerialization.data(withJSONObject: ["alg": "ES384", "typ": "JWT", "kid": "iTqXXI0zbAnJCKDaobfhkM1f-6rMSpTfyZMRp_2tKI8"]),
            let exampleJWTClaims = try? JSONSerialization.data(withJSONObject: ["sub": "1234567890", "name": "John Doe", "admin": true, "iat": 1516239022])
            else {
                return XCTFail("Failed to serialize JWT to JSON")
        }
        
        let unsignedJWT = exampleJWTHeader.base64urlEncodedString() + "." + exampleJWTClaims.base64urlEncodedString()
        guard let unsignedData = unsignedJWT.data(using: .utf8) else {
            return XCTFail("Failed to encode unsignedJWT to utf8")
        }
        
        guard let ecdsaPrivateKey = ECPrivateKey(pemKey: ecPem384PrivateKey) else {
            return XCTFail()
        }
        guard let ecdsaPublicKey = ECPublicKey(pemKey: ecPem384PublicKey) else {
            return XCTFail()
        }
        let signature = Plaintext(data: unsignedData).signUsing(ecPrivateKey: ecdsaPrivateKey)
        print(unsignedJWT)
        print(signature?.data.base64urlEncodedString())
        let verified = signature?.verify(plaintext: Plaintext(data: unsignedData), using: ecdsaPublicKey)
        XCTAssert(verified == true)
    }
    
    func test_Pem384ECDSAVerify() {
        // generated from jwt.io
        guard let JWTDigest =  "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCIsImtpZCI6ImlUcVhYSTB6YkFuSkNLRGFvYmZoa00xZi02ck1TcFRmeVpNUnBfMnRLSTgifQ.eyJhZG1pbiI6dHJ1ZSwiaWF0IjoxNTE2MjM5MDIyLCJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0".data(using: .utf8),
            let JWTSignature = Data(base64urlEncoded: "KOJv0MUveeDr5HQwbA4lX31FDJAP-46MIr5rdd1T_4ppSGIfCrN81uyqbs7pbnYta_-_f6EZe6O60BwiotmlE4qLBW_Db2XGOvU0R5z2RMH8rtaNxkKnorsh-ZHn40Xu") else {
                return XCTFail("Failed to create JWT digest")
        }
        
        guard let ecdsaPublicKey = ECPublicKey(pemKey: ecPem384PublicKey) else {
            return XCTFail()
        }
        let verified = Signature(data: JWTSignature).verify(plaintext: Plaintext(data: JWTDigest), using: ecdsaPublicKey)
        XCTAssert(verified == true)
    }
}

extension Data {
    func base64urlEncodedString() -> String {
        let result = self.base64EncodedString()
        return result.replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
    
    init?(base64urlEncoded: String) {
        let paddingLength = 4 - base64urlEncoded.count % 4
        let padding = (paddingLength < 4) ? String(repeating: "=", count: paddingLength) : ""
        let base64EncodedString = base64urlEncoded
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
            + padding
        self.init(base64Encoded: base64EncodedString)
    }
}
