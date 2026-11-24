# -*- encoding: utf-8 -*-
# stub: json-jwt 1.16.6 ruby lib

Gem::Specification.new do |s|
  s.name = "json-jwt".freeze
  s.version = "1.16.6".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["nov matake".freeze]
  s.date = "2024-03-03"
  s.description = "JSON Web Token and its family (JSON Web Signature, JSON Web Encryption and JSON Web Key) in Ruby".freeze
  s.email = ["nov@matake.jp".freeze]
  s.homepage = "https://github.com/nov/json-jwt".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.4".freeze)
  s.rubygems_version = "3.5.3".freeze
  s.summary = "JSON Web Token and its family (JSON Web Signature, JSON Web Encryption and JSON Web Key) in Ruby".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<activesupport>.freeze, [">= 4.2".freeze])
  s.add_runtime_dependency(%q<base64>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<bindata>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<aes_key_wrap>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<faraday>.freeze, ["~> 2.0".freeze])
  s.add_runtime_dependency(%q<faraday-follow_redirects>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rake>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<simplecov>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<webmock>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rspec>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rspec-its>.freeze, [">= 0".freeze])
end
