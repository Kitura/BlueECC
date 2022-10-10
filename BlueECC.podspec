Pod::Spec.new do |s|
  s.name        = "BlueECC"
  s.version     = "1.2.202"
  s.summary     = "Swift cross-platform ECC crypto library using CommonCrypto/libcrypto via Package Manager."
  s.homepage    = "https://github.com/Kitura/BlueECC"
  s.license     = { :type => "Apache License, Version 2.0" }
  s.author     = "IBM & Kitura project authors"
  s.module_name  = 'CryptorECC'
  s.requires_arc = true
  s.osx.deployment_target = "11.5"
  s.ios.deployment_target = "14.5"
  s.tvos.deployment_target = "14.5"
  s.watchos.deployment_target = "7.5"
  s.source   = { :git => "https://github.com/Kitura/BlueECC.git", :tag => s.version }
  s.source_files = "Sources/**/*.swift"
  s.swift_versions = '5.2'
end
