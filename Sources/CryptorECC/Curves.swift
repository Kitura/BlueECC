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

/// An extensible list of elliptic curves supported by this repository.
@available(OSX 10.13, *)
public struct Curve: Equatable {
    
    private let internalRepresentation: InternalRepresentation
    
    let algorithm: ECAlgorithm
    
    private enum InternalRepresentation: String {
        case prime256v1, secp384r1, secp521r1
    }
    
    /// A prime256v1 curve.
    public static let prime256v1 = Curve(internalRepresentation: .prime256v1, algorithm: .p256)
    
    /// A secp384r1 curve.
    public static let secp384r1 = Curve(internalRepresentation: .secp384r1, algorithm: .p384)
    
    /// A secp521r1 curve.
    public static let secp521r1 = Curve(internalRepresentation: .secp521r1, algorithm: .p521)
    
    /// Checks if two Curves are equal, required for Equatable protocol.
    public static func == (lhs: Curve, rhs: Curve) -> Bool {
        return lhs.internalRepresentation == rhs.internalRepresentation
    }
}
