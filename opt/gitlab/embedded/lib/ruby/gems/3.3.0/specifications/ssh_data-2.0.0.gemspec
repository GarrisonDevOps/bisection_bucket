# -*- encoding: utf-8 -*-
# stub: ssh_data 2.0.0 ruby lib

Gem::Specification.new do |s|
  s.name = "ssh_data".freeze
  s.version = "2.0.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["mastahyeti".freeze]
  s.date = "2025-01-06"
  s.email = "opensource+ssh_data@github.com".freeze
  s.homepage = "https://github.com/github/ssh_data".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.1".freeze)
  s.rubygems_version = "3.6.2".freeze
  s.summary = "Library for parsing SSH certificates".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<base64>.freeze, ["~> 0.1".freeze])
  s.add_development_dependency(%q<ed25519>.freeze, ["~> 1.2".freeze])
  s.add_development_dependency(%q<pry>.freeze, ["~> 0.14".freeze])
  s.add_development_dependency(%q<rspec>.freeze, ["~> 3.10".freeze])
  s.add_development_dependency(%q<rspec-parameterized>.freeze, ["~> 1.0".freeze])
  s.add_development_dependency(%q<rspec-mocks>.freeze, ["~> 3.10".freeze])
end
