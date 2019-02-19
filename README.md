<p align="center">
    <a href="http://kitura.io/">
        <img src="https://raw.githubusercontent.com/IBM-Swift/Kitura/master/Sources/Kitura/resources/kitura-bird.svg?sanitize=true" height="100" alt="Kitura">
    </a>
</p>


<p align="center">
    <a href="https://ibm-swift.github.io/BlueECC/index.html">
    <img src="https://img.shields.io/badge/apidoc-BlueECC-1FBCE4.svg?style=flat" alt="APIDoc">
    </a>
    <a href="https://travis-ci.org/IBM-Swift/Kitura-BlueECC">
    <img src="https://travis-ci.org/IBM-Swift/Kitura-BlueECC.svg?branch=master" alt="Build Status - Master">
    </a>
    <img src="https://img.shields.io/badge/os-macOS-green.svg?style=flat" alt="macOS">
    <img src="https://img.shields.io/badge/os-linux-green.svg?style=flat" alt="Linux">
    <img src="https://img.shields.io/badge/license-Apache2-blue.svg?style=flat" alt="Apache 2">
    <a href="http://swift-at-ibm-slack.mybluemix.net/">
    <img src="http://swift-at-ibm-slack.mybluemix.net/badge.svg" alt="Slack Status">
    </a>
</p>

# BlueECC

A cross platform swift implementation of Elliptic Curve Digital Signature Algorithm (ECDSA).

## Usage

#### Add dependencies

Add the `BlueECC` package to the dependencies within your application’s `Package.swift` file. Substitute `"x.x.x"` with the latest `BlueECC` [release](https://github.com/IBM-Swift/BlueECC/releases).

```swift
.package(url: "https://github.com/IBM-Swift/BlueECC.git", from: "x.x.x")
```

Add `CryptorECC` to your target's dependencies:

```swift
.target(name: "example", dependencies: ["CryptorECC"]),
```

#### Import package

```swift
import CryptorECC
```

## API Documentation

#### Elliptic curve private key

Generate your Elliptic curve private key using a third party provider:

You can generate a `p-256` private key as a `.p8` file for Apple services from [https://developer.apple.com/account/ios/authkey](https://developer.apple.com/account/ios/authkey/). This will produce a key that should be formatted as follows:
```swift
let p8PrivateKey = 
"""
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQglf7ztYnsaHX2yiHJ
meHFl5dg05y4a/hD7wwuB7hSRpmhRANCAASKRzmboLbG0NZ54B5PXxYSU7fvO8U7
PyniQCWG+Agc3bdcgKU0RKApWYuBJKrZqyqLB2tTlgdtwcWSB0AEzVI8
-----END PRIVATE KEY-----
"""
```
The key can then be used to initialize an `ECPrivateKey` instance:
```swift
let ecdsaPrivateKey = try ECPrivateKey(p8Key: p8PrivateKey)
```

Alternatively, you can use OpenSSL [Command Line Elliptic Curve Operations](https://wiki.openssl.org/index.php/Command_Line_Elliptic_Curve_Operations).  
OpenSSL can be installed via brew:

```
$ brew install openssl
```

The following commands generate private keys for the three supported curves as `.pem` files:
```
// p-256
$ openssl ecparam -name prime256v1 -genkey -noout -out key.pem
// p-384
$ openssl ecparam -name secp384r1 -genkey -noout -out key.pem
// p-521
$ openssl ecparam -name secp521r1 -genkey -noout -out key.pem
```
These keys will be formatted as follows:
```
let pemPrivateKey = 
"""
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJX+87WJ7Gh19sohyZnhxZeXYNOcuGv4Q+8MLge4UkaZoAoGCCqGSM49
AwEHoUQDQgAEikc5m6C2xtDWeeAeT18WElO37zvFOz8p4kAlhvgIHN23XIClNESg
KVmLgSSq2asqiwdrU5YHbcHFkgdABM1SPA==
-----END EC PRIVATE KEY-----
"""
```

####  Elliptic curve public  key

Use OpenSSL to generate an EC public key `.pem` file from any of the above EC private key files:
```
$ openssl ec -in key.pem -pubout -out public.pem
```
This will produce a public key formatted as follows:
```
let pemPublicKey = 
"""
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEikc5m6C2xtDWeeAeT18WElO37zvF
Oz8p4kAlhvgIHN23XIClNESgKVmLgSSq2asqiwdrU5YHbcHFkgdABM1SPA==
-----END PUBLIC KEY-----
"""
```
These keys can then be used to initialize an `ECPrivateKey` instance:
```swift
let ecdsaPublicKey = try ECPublicKey(pemKey: pemPublicKey)
```

#### Signing String or Data

BlueECC extends `String` and `Data` to be `ECSignable`:

```swift
public protocol ECSignable {
    func sign(with: ECPrivateKey) throws -> ECSignature
}
```

This lets you sign your plaintext using an EC private key:
```swift
let message = "hello world"
let signature = try message.sign(with: ecdsaPrivateKey)
```

#### Verifying the signature

Use the public key to verify the signature for the plaintext:
```swift
let verified = signature.verify(plaintext: message, using: ecdsaPublicKey)
if verified {
    print("Signature is valid for provided plaintext")
}
```

For more information visit our [API reference](https://ibm-swift.github.io/BlueECC/index.html).

## Community
We love to talk server-side Swift, and Kitura. Join our [Slack](http://swift-at-ibm-slack.mybluemix.net/) to meet the team!

## License
This library is licensed under Apache 2.0. Full license text is available in [LICENSE](https://github.com/IBM-Swift/BlueECC/blob/master/LICENSE.txt).
