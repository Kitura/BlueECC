import XCTest
import CryptorECC

@available(OSX 10.13, *)
final class CryptorECCTests: XCTestCase {
    static var allTests = [
            ("test_simpleCycle", test_simpleCycle),
            ("test_PemECDSACycle", test_PemECDSACycle),
            ("test_P8ECDSACycle", test_P8ECDSACycle),
            ("test_AppleP8ECDSACycle", test_AppleP8ECDSACycle),
            ("test_PemECDSAVerify", test_PemECDSAVerify),
            ("test_P8ECDSAVerify", test_P8ECDSAVerify),
            ("test_Pem384ECDSAVerify", test_Pem384ECDSAVerify),
            ("test_Pem384ECDSACycle", test_Pem384ECDSACycle),
            ("test_P8ES384Cycle", test_P8ES384Cycle),
            ("test_Pem512ECDSAVerify", test_Pem512ECDSAVerify),
            ("test_P8ES512Cycle", test_P8ES512Cycle),
            ("test_Pem512ECDSACycle", test_Pem512ECDSACycle),
            ("test_IncorrectPublicKey", test_IncorrectPublicKey),
            ("test_IncorrectPlaintext", test_IncorrectPlaintext),
            ("test_EncryptionCycle", test_EncryptionCycle),
            ("test_MacEncrypted", test_MacEncrypted),
            ("test_LinuxEncrypted", test_LinuxEncrypted),
            ("test_EncryptionCycle384", test_EncryptionCycle384),
            ("test_EncryptionCycle512", test_EncryptionCycle512),
            ("test_ExtractPublicKey", test_ExtractPublicKey),
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
    let appleECP8PrivateKey = """
-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg2sD+kukkA8GZUpmm
jRa4fJ9Xa/JnIG4Hpi7tNO66+OGgCgYIKoZIzj0DAQehRANCAATZp0yt0btpR9kf
ntp4oUUzTV0+eTELXxJxFvhnqmgwGAm1iVW132XLrdRG/ntlbQ1yzUuJkHtYBNve
y+77Vzsd
-----END PRIVATE KEY-----
"""
    let appleECP8PublicKey = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2adMrdG7aUfZH57aeKFFM01dPnkx
C18ScRb4Z6poMBgJtYlVtd9ly63URv57ZW0Ncs1LiZB7WATb3svu+1c7HQ==
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
    let ecP8ES384PrivateKey = """
-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDBQ6YAp5oWCF3EzJdQu
pQu2dD6BVf7i5QDb9wMoFicaKlnXzH9weMDzVM/W4pwLAF+hZANiAAQGqeXUjuGM
qj0w41MLjTFDT7oUoiFLM/Mq8xVnMX3IJSYDUc7eWIsJHS9VUAtNFt1dHXSxRnhS
Bv0ct0VxITCv8W42LUutbUg+EPzehH6ApDeKJSQxwjnwhgr0J06ThCA=
-----END PRIVATE KEY-----
"""
    let ecPem512PrivateKey = """
-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBRS6x89l3JHzSST5kKhubFPaZweNeZ02SCbmdSh5SVrK9uB9/hjCF
qC1vd6kWLPV6mONJEVhv5ZChjq02hb8xZRKgBwYFK4EEACOhgYkDgYYABAHyyYaq
SAMF9Olbt3zyx2gL5123JmJPOXuJlxlvA48jU8K85aBYSJ/ZNrjOKtqHdDIASUBs
HMlLaH/te3VQQ6O2sQHvFC2oh9/1wMfDchP7ImBwktdB+x1/lodGyMLzGV/uxtsj
hwFbX0t7mzDLAm0USboXyclnQ65y8C1UEVOBK30WMw==
-----END EC PRIVATE KEY-----
"""
    let ecPem512PublicKey = """
-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB8smGqkgDBfTpW7d88sdoC+ddtyZi
Tzl7iZcZbwOPI1PCvOWgWEif2Ta4zirah3QyAElAbBzJS2h/7Xt1UEOjtrEB7xQt
qIff9cDHw3IT+yJgcJLXQfsdf5aHRsjC8xlf7sbbI4cBW19Le5swywJtFEm6F8nJ
Z0OucvAtVBFTgSt9FjM=
-----END PUBLIC KEY-----
"""
    let ecP8ES512PrivateKey = """
-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBRS6x89l3JHzSST5k
KhubFPaZweNeZ02SCbmdSh5SVrK9uB9/hjCFqC1vd6kWLPV6mONJEVhv5ZChjq02
hb8xZRKhgYkDgYYABAHyyYaqSAMF9Olbt3zyx2gL5123JmJPOXuJlxlvA48jU8K8
5aBYSJ/ZNrjOKtqHdDIASUBsHMlLaH/te3VQQ6O2sQHvFC2oh9/1wMfDchP7ImBw
ktdB+x1/lodGyMLzGV/uxtsjhwFbX0t7mzDLAm0USboXyclnQ65y8C1UEVOBK30W
Mw==
-----END PRIVATE KEY-----
"""
    
    func test_simpleCycle() { 
        do {
            let ecdsaPrivateKey = try ECPrivateKey(key: ecPemPrivateKey)
            let ecdsaPublicKey = try ECPublicKey(key: ecPemPublicKey)
            let signature = try "Hello world".sign(with: ecdsaPrivateKey)
            let verified = signature.verify(plaintext: "Hello world", using: ecdsaPublicKey)
            XCTAssertTrue(verified)
        } catch {
            return XCTFail("test_simpleCycle failed: \(error)")
        }
    }
    
    func test_PemECDSACycle() {
        do {
            let exampleJWTHeader = try JSONSerialization.data(withJSONObject: ["alg": "ES256", "typ": "JWT"])
            let exampleJWTClaims = try JSONSerialization.data(withJSONObject: ["sub": "1234567890", "admin": true, "iat": 1516239022])
            let unsignedJWT = exampleJWTHeader.base64urlEncodedString() + "." + exampleJWTClaims.base64urlEncodedString()
            let ecdsaPrivateKey = try ECPrivateKey(key: ecPemPrivateKey)
            let ecdsaPublicKey = try ECPublicKey(key: ecPemPublicKey)
            let signature = try unsignedJWT.sign(with: ecdsaPrivateKey)
            let verified = signature.verify(plaintext: unsignedJWT, using: ecdsaPublicKey)
            XCTAssertTrue(verified)
        } catch {
            return XCTFail("test_PemECDSACycle failed: \(error)")
        }
    }
    
    func test_P8ECDSACycle() {
        do {
            let exampleJWTHeader = try JSONSerialization.data(withJSONObject: ["alg": "ES256", "typ": "JWT"])
            let exampleJWTClaims = try JSONSerialization.data(withJSONObject: ["sub": "1234567890", "admin": true, "iat": 1516239022])
            let unsignedJWT = exampleJWTHeader.base64urlEncodedString() + "." + exampleJWTClaims.base64urlEncodedString()
            let ecdsaPrivateKey = try ECPrivateKey(key: ecP8PrivateKey)
            let ecdsaPublicKey = try ECPublicKey(key: ecP8PublicKey)
            let signature = try unsignedJWT.sign(with: ecdsaPrivateKey)
            let verified = signature.verify(plaintext: unsignedJWT, using: ecdsaPublicKey)
            XCTAssertTrue(verified)
        } catch {
            return XCTFail("test_P8ECDSACycle failed: \(error)")
        }
    }
    
    func test_AppleP8ECDSACycle() {
        do {
        let exampleJWTHeader = try JSONSerialization.data(withJSONObject: ["alg": "ES256", "typ": "JWT"])
        let exampleJWTClaims = try JSONSerialization.data(withJSONObject: ["sub": "1234567890", "admin": true, "iat": 1516239022])
        let unsignedJWT = exampleJWTHeader.base64urlEncodedString() + "." + exampleJWTClaims.base64urlEncodedString()
        let ecdsaPrivateKey = try ECPrivateKey(key: appleECP8PrivateKey)
        let ecdsaPublicKey = try ECPublicKey(key: appleECP8PublicKey)
        let signature = try unsignedJWT.sign(with: ecdsaPrivateKey)
        let verified = signature.verify(plaintext: unsignedJWT, using: ecdsaPublicKey)
        XCTAssertTrue(verified)
        } catch {
            return XCTFail("test_AppleP8ECDSACycle failed: \(error)")
        }
    }
    
    func test_PemECDSAVerify() {
        do {
            // generated from jwt.io
            guard let JWTDigest =  "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0".data(using: .utf8),
                let JWTSignature = Data(base64urlEncoded: "jGeUQXuf4WLuqhCHOdrIr2alE4JQyKQwkj-GbZIXQIpwrKLymEd41bka2PSIqRAA6H1A2kLuXhzwFw02qQdMhw") else {
                    return XCTFail("Failed to create JWT digest")
            }
            let r = JWTSignature.subdata(in: 0 ..< JWTSignature.count/2)
            let s = JWTSignature.subdata(in: JWTSignature.count/2 ..< JWTSignature.count)
            let ecdsaPublicKey = try ECPublicKey(key: ecPemPublicKey)
            let sig = try ECSignature(r: r, s: s)
            let verified = sig.verify(plaintext: JWTDigest, using: ecdsaPublicKey)
            XCTAssertTrue(verified)
        } catch {
            return XCTFail("test_PemECDSAVerify failed: \(error)")
        }
    }
    
    func test_P8ECDSAVerify() {
        do {
            // generated from jwt.io
            guard let JWTDigest =  "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0".data(using: .utf8),
                let JWTSignature = Data(base64urlEncoded: "faLW3RiQtUG6U71gCrGEBY7AWNfYphygJQKoW8apoB4beX_-GFhkBwkcZATXKIL8UoFLHqmdKK97vO2Nv3OWDA") else {
                    return XCTFail("Failed to create JWT digest")
            }
            let r = JWTSignature.subdata(in: 0 ..< JWTSignature.count/2)
            let s = JWTSignature.subdata(in: JWTSignature.count/2 ..< JWTSignature.count)
            let ecdsaPublicKey = try ECPublicKey(key: ecPemPublicKey)
            let sig = try ECSignature(r: r, s: s)
            let verified = sig.verify(plaintext: JWTDigest, using: ecdsaPublicKey)
            XCTAssertTrue(verified)
        } catch {
            return XCTFail("test_P8ECDSAVerify failed: \(error)")
        }
    }
    
    func test_Pem384ECDSACycle() {
        do {
        guard let exampleJWTHeader = try? JSONSerialization.data(withJSONObject: ["alg": "ES384", "typ": "JWT", "kid": "iTqXXI0zbAnJCKDaobfhkM1f-6rMSpTfyZMRp_2tKI8"]),
            let exampleJWTClaims = try? JSONSerialization.data(withJSONObject: ["sub": "1234567890", "name": "John Doe", "admin": true, "iat": 1516239022])
            else {
                return XCTFail("Failed to serialize JWT to JSON")
        }
        
        let unsignedJWT = exampleJWTHeader.base64urlEncodedString() + "." + exampleJWTClaims.base64urlEncodedString()
        
        let ecdsaPrivateKey = try ECPrivateKey(key: ecPem384PrivateKey)
        let ecdsaPublicKey = try ECPublicKey(key: ecPem384PublicKey)
        let signature = try unsignedJWT.sign(with: ecdsaPrivateKey)
        let verified = signature.verify(plaintext: unsignedJWT, using: ecdsaPublicKey)
        XCTAssertTrue(verified)
        } catch {
            return XCTFail("test_Pem384ECDSACycle failed: \(error)")
        }
    }
    
    func test_P8ES384Cycle() {
        do {
            guard let exampleJWTHeader = try? JSONSerialization.data(withJSONObject: ["alg": "ES384", "typ": "JWT", "kid": "iTqXXI0zbAnJCKDaobfhkM1f-6rMSpTfyZMRp_2tKI8"]),
                let exampleJWTClaims = try? JSONSerialization.data(withJSONObject: ["sub": "1234567890", "name": "John Doe", "admin": true, "iat": 1516239022])
                else {
                    return XCTFail("Failed to serialize JWT to JSON")
            }
            
            let unsignedJWT = exampleJWTHeader.base64urlEncodedString() + "." + exampleJWTClaims.base64urlEncodedString()
            let ecdsaPrivateKey = try ECPrivateKey(key: ecP8ES384PrivateKey)
            let ecdsaPublicKey = try ECPublicKey(key: ecPem384PublicKey)
            let signature = try unsignedJWT.sign(with: ecdsaPrivateKey)
            let verified = signature.verify(plaintext: unsignedJWT, using: ecdsaPublicKey)
            XCTAssertTrue(verified)
        } catch {
            return XCTFail("test_P8ES384Cycle failed: \(error)")
        }
    }
    
    func test_Pem384ECDSAVerify() {
        do {
            // generated from jwt.io
            guard let JWTDigest =  "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCIsImtpZCI6ImlUcVhYSTB6YkFuSkNLRGFvYmZoa00xZi02ck1TcFRmeVpNUnBfMnRLSTgifQ.eyJhZG1pbiI6dHJ1ZSwiaWF0IjoxNTE2MjM5MDIyLCJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0".data(using: .utf8),
                let JWTSignature = Data(base64urlEncoded: "KOJv0MUveeDr5HQwbA4lX31FDJAP-46MIr5rdd1T_4ppSGIfCrN81uyqbs7pbnYta_-_f6EZe6O60BwiotmlE4qLBW_Db2XGOvU0R5z2RMH8rtaNxkKnorsh-ZHn40Xu") else {
                    return XCTFail("Failed to create JWT digest")
            }
            let r = JWTSignature.subdata(in: 0 ..< JWTSignature.count/2)
            let s = JWTSignature.subdata(in: JWTSignature.count/2 ..< JWTSignature.count)
            let ecdsaPublicKey = try ECPublicKey(key: ecPem384PublicKey)
            let sig = try ECSignature(r: r, s: s)
            let verified = sig.verify(plaintext: JWTDigest, using: ecdsaPublicKey)
            XCTAssertTrue(verified)
        } catch {
            return XCTFail("test_Pem384ECDSAVerify failed: \(error)")
        }
    }
    
    func test_Pem512ECDSACycle() {
        do {
            guard let exampleJWTHeader = try? JSONSerialization.data(withJSONObject: ["alg": "ES512", "typ": "JWT", "kid": "xZDfZpry4P9vZPZyG2fNBRj-7Lz5omVdm7tHoCgSNfY"]),
                let exampleJWTClaims = try? JSONSerialization.data(withJSONObject: ["sub": "1234567890", "name": "John Doe", "admin": true, "iat": 1516239022])
                else {
                    return XCTFail("Failed to serialize JWT to JSON")
            }
            
            let unsignedJWT = exampleJWTHeader.base64urlEncodedString() + "." + exampleJWTClaims.base64urlEncodedString()
            
            let ecdsaPrivateKey = try ECPrivateKey(key: ecPem512PrivateKey)
            let ecdsaPublicKey = try ECPublicKey(key: ecPem512PublicKey)
            let signature = try unsignedJWT.sign(with: ecdsaPrivateKey)
            let verified = signature.verify(plaintext: unsignedJWT, using: ecdsaPublicKey)
            XCTAssertTrue(verified)
        } catch {
            return XCTFail("test_Pem512ECDSACycle failed: \(error)")
        }
    }
    
    func test_P8ES512Cycle() {
        do {
            guard let exampleJWTHeader = try? JSONSerialization.data(withJSONObject: ["alg": "ES512", "typ": "JWT", "kid": "iTqXXI0zbAnJCKDaobfhkM1f-6rMSpTfyZMRp_2tKI8"]),
                let exampleJWTClaims = try? JSONSerialization.data(withJSONObject: ["sub": "1234567890", "name": "John Doe", "admin": true, "iat": 1516239022])
                else {
                    return XCTFail("Failed to serialize JWT to JSON")
            }
            
            let unsignedJWT = exampleJWTHeader.base64urlEncodedString() + "." + exampleJWTClaims.base64urlEncodedString()
            
            let ecdsaPrivateKey = try ECPrivateKey(key: ecP8ES512PrivateKey)
            let ecdsaPublicKey = try ECPublicKey(key: ecPem512PublicKey)
            let signature = try unsignedJWT.sign(with: ecdsaPrivateKey)
            let verified = signature.verify(plaintext: unsignedJWT, using: ecdsaPublicKey)
            XCTAssertTrue(verified)
        } catch {
            return XCTFail("test_P8ES512Cycle failed: \(error)")
        }
    }
    
    func test_Pem512ECDSAVerify() {
        do {
            // generated from jwt.io
            guard let JWTDigest =  "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsImFkbWluIjp0cnVlLCJzdWIiOiIxMjM0NTY3ODkwIn0".data(using: .utf8),
                let JWTSignature = Data(base64urlEncoded: "Aem_D3xHktMbg_RAjvmpvLDcazsLKyU7xskklO54-G3FN2Z20u64zxH9t5raHLoMyfYZIaRhLMEqPVq8DkFS4Z0DAUhR3ZfuEEIvQzVY3S6cS_0WuLPstwHsURrEZqPs0afoxR0E8HSauv83hXmm9OOkTqUYstdFyDvKM6qEB6qktla0") else {
                    return XCTFail("Failed to create JWT digest")
            }
            let r = JWTSignature.subdata(in: 0 ..< JWTSignature.count/2)
            let s = JWTSignature.subdata(in: JWTSignature.count/2 ..< JWTSignature.count)
            let ecdsaPublicKey = try ECPublicKey(key: ecPem512PublicKey)
            let sig = try ECSignature(r: r, s: s)
            let verified = sig.verify(plaintext: JWTDigest, using: ecdsaPublicKey)
            XCTAssertTrue(verified)
        } catch {
            return XCTFail("test_Pem512ECDSAVerify failed: \(error)")
        }
    }
    
    func test_IncorrectPublicKey() {
        do {
            guard let exampleJWTHeader = try? JSONSerialization.data(withJSONObject: ["alg": "ES256", "typ": "JWT"]),
                let exampleJWTClaims = try? JSONSerialization.data(withJSONObject: ["sub": "1234567890", "admin": true, "iat": 1516239022])
                else {
                    return XCTFail("Failed to serialize JWT to JSON")
            }
            
            let unsignedJWT = exampleJWTHeader.base64urlEncodedString() + "." + exampleJWTClaims.base64urlEncodedString()
            
            let ecdsaPrivateKey = try ECPrivateKey(key: ecPemPrivateKey)
            let ecdsaPublicKey = try ECPublicKey(key: ecPem384PublicKey)
            let signature = try unsignedJWT.sign(with: ecdsaPrivateKey)
            let verified = signature.verify(plaintext: unsignedJWT, using: ecdsaPublicKey)
            XCTAssertFalse(verified)
        } catch {
            return XCTFail("test_IncorrectPublicKey failed: \(error)")
        }
    }
    
    func test_IncorrectPlaintext() {
        do {
            let plaintext = "Hello world"
            let changedPlaintext = "Hello Kitura"
            guard let plaintextData = plaintext.data(using: .utf8),
                let changedPlaintextData = changedPlaintext.data(using: .utf8)
                else {
                    return XCTFail("Failed to encode unsignedJWT to utf8")
            }
            
            let ecdsaPrivateKey = try ECPrivateKey(key: ecPemPrivateKey)
            let ecdsaPublicKey = try ECPublicKey(key: ecPemPublicKey)
            let signature = try plaintextData.sign(with: ecdsaPrivateKey)
            let verified = signature.verify(plaintext: changedPlaintextData, using: ecdsaPublicKey)
            XCTAssertFalse(verified)
        } catch {
            return XCTFail("test_IncorrectPlaintext failed: \(error)")
        }
    }
    
    func test_EncryptionCycle() {
        do {
            let ecdsaPrivateKey = try ECPrivateKey(key: ecPemPrivateKey)
            let ecdsaPublicKey = try ECPublicKey(key: ecPemPublicKey)
            let encrypted = try "Hello world".encrypt(with: ecdsaPublicKey)
            let decrypted = try encrypted.decrypt(with: ecdsaPrivateKey)
            XCTAssert(String(data: decrypted, encoding: .utf8) == "Hello world")
        } catch {
            return XCTFail("test_EncryptionCycle failed: \(error)")
        }
    }
    
    func test_MacEncrypted() {
        do {
            let ecdsaPrivateKey = try ECPrivateKey(key: ecPemPrivateKey)
            guard let encrypted = Data(base64Encoded: "BDDIvmY4i0y064se0TcXoSnbYP0eyMMoCMT+3Jfxe7I8hlHYXMPpVMsOvjLWTe0Mj0/gMS1bMq9BCO2bPC0gC+Y2ZzMu9uGoqK7H/BnEjUIBjNGUKrA2VtahQaU=") else {
                return XCTFail("MacEncrypted was invalid Base64 String")
            }
            let decrypted = try encrypted.decrypt(with: ecdsaPrivateKey)
            XCTAssert(String(data: decrypted, encoding: .utf8) == "Hello world")
        } catch {
            return XCTFail("test_MacEncrypted failed: \(error)")
        }
    }
    func test_LinuxEncrypted() {
        do {
            let ecdsaPrivateKey = try ECPrivateKey(key: ecPemPrivateKey)
            guard let encrypted = Data(base64Encoded: "BIcZ+Nlo+pQLaaY3hUcvYXbeleakSPp18KBlLGEV+IvuFNp+gdKWpdqJ602UWAd6OJBBaGvISzzLF1kVxLuHUFopIK3rPjxF4IXRLYMQpmoyQOl41vby/3kkZt0=") else {
                return XCTFail("MacEncrypted was invalid Base64 String")
            }
            let decrypted = try encrypted.decrypt(with: ecdsaPrivateKey)
            XCTAssert(String(data: decrypted, encoding: .utf8) == "Hello world")
        } catch {
            return XCTFail("test_LinuxEncrypted failed: \(error)")
        }
    }
    
    func test_EncryptionCycle384() {
        do {
            let ecdsaPrivateKey = try ECPrivateKey(key: ecPem384PrivateKey)
            let ecdsaPublicKey = try ECPublicKey(key: ecPem384PublicKey)
            let encrypted = try "Hello world".encrypt(with: ecdsaPublicKey)
            let decrypted = try encrypted.decrypt(with: ecdsaPrivateKey)
            XCTAssert(String(data: decrypted, encoding: .utf8) == "Hello world")
        } catch {
            return XCTFail("test_EncryptionCycle384 failed: \(error)")
        }
    }
    
    // Cross platform encryption is not currently working with 384 curves

    func test_EncryptionCycle512() {
        do {
            let ecdsaPrivateKey = try ECPrivateKey(key: ecPem512PrivateKey)
            let ecdsaPublicKey = try ECPublicKey(key: ecPem512PublicKey)
            let encrypted = try "Hello world".encrypt(with: ecdsaPublicKey)
            let decrypted = try encrypted.decrypt(with: ecdsaPrivateKey)
            XCTAssert(String(data: decrypted, encoding: .utf8) == "Hello world")
        } catch {
            return XCTFail("test_EncryptionCycle384 failed: \(error)")
        }
    }
    
    // Cross platform encryption is not currently working with 512 curves
    
    func test_ExtractPublicKey() {
        do {
            let ecdsaPrivateKey = try ECPrivateKey(key: ecPemPrivateKey)
            let ecdsaPublicKey = try ecdsaPrivateKey.extractPublicKey()
            XCTAssert(ecdsaPublicKey.pemString == ecPemPublicKey)
            
            let p8PrivateKey = try ECPrivateKey(key: ecP8PrivateKey)
            let p8PublicKey = try p8PrivateKey.extractPublicKey()
            XCTAssert(p8PublicKey.pemString == ecP8PublicKey)

            let privateKey384 = try ECPrivateKey(key: ecPem384PrivateKey)
            let publicKey384 = try privateKey384.extractPublicKey()
            XCTAssert(publicKey384.pemString == ecPem384PublicKey)
            
            let privateKey512 = try ECPrivateKey(key: ecPem512PrivateKey)
            let publicKey512 = try privateKey512.extractPublicKey()
            XCTAssert(publicKey512.pemString == ecPem512PublicKey)
        } catch {
            return XCTFail("test_ExtractPublicKey failed: \(error)")
        }
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
