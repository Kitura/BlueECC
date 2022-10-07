Pod::Spec.new do |s|
  s.name        = "BlueECC"
  s.version     = "1.2.201"
  s.summary     = "Swift cross-platform ECC crypto library using CommonCrypto/libcrypto via Package Manager."
  s.homepage    = "https://github.com/Kitura/BlueECC"
  s.license     = { :type => "Apache License, Version 2.0" }
  s.author     = "IBM & Kitura project authors"
  s.module_name  = 'CryptorECC'
  s.requires_arc = true
  s.osx.deployment_target = "10.13"
  s.ios.deployment_target = "11.0"
  s.tvos.deployment_target = "11.0"
  s.watchos.deployment_target = "4.0"
  s.source   = { :git => "https://github.com/Kitura/BlueECC.git", :tag => s.version }
  s.source_files = "Sources/**/*.swift"
end
