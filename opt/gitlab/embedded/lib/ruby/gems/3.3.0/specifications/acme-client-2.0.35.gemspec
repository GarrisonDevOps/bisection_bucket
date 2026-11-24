# -*- encoding: utf-8 -*-
# stub: acme-client 2.0.35 ruby lib

Gem::Specification.new do |s|
  s.name = "acme-client".freeze
  s.version = "2.0.35".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Charles Barbier".freeze]
  s.date = "1980-01-02"
  s.email = ["unixcharles@gmail.com".freeze]
  s.homepage = "http://github.com/unixcharles/acme-client".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.3.0".freeze)
  s.rubygems_version = "3.6.9".freeze
  s.summary = "Client for the ACME protocol.".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_development_dependency(%q<rake>.freeze, ["~> 13.0".freeze])
  s.add_development_dependency(%q<rspec>.freeze, ["~> 3.9".freeze])
  s.add_development_dependency(%q<vcr>.freeze, ["~> 6.0".freeze])
  s.add_development_dependency(%q<bigdecimal>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<csv>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<webmock>.freeze, ["~> 3.8".freeze])
  s.add_development_dependency(%q<webrick>.freeze, ["~> 1.7".freeze])
  s.add_runtime_dependency(%q<base64>.freeze, ["~> 0.2".freeze])
  s.add_runtime_dependency(%q<faraday>.freeze, [">= 1.0".freeze, "< 3.0.0".freeze])
  s.add_runtime_dependency(%q<faraday-retry>.freeze, [">= 1.0".freeze, "< 3.0.0".freeze])
end
