# -*- encoding: utf-8 -*-
# stub: telesign 2.4.0 ruby lib

Gem::Specification.new do |s|
  s.name = "telesign".freeze
  s.version = "2.4.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Telesign".freeze]
  s.date = "2017-05-25"
  s.description = "Telesign Ruby SDK".freeze
  s.email = "support@telesign.com".freeze
  s.homepage = "http://rubygems.org/gems/telesign".freeze
  s.licenses = ["MIT".freeze]
  s.rubygems_version = "3.4.10".freeze
  s.summary = "Telesign Ruby SDK".freeze

  s.installed_by_version = "3.7.2".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<net-http-persistent>.freeze, [">= 3.0.0".freeze, "< 5.0".freeze])
  s.add_development_dependency(%q<rake>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<uuid>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<mocha>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<webmock>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<codecov>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<simplecov>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<test-unit>.freeze, [">= 0".freeze])
end
